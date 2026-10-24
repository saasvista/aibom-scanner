"""SARIF v2.1.0 output for GitHub Code Scanning integration."""

import json
import re
from dataclasses import asdict

from aibom_scanner import __version__
from aibom_scanner.formatters.json_fmt import neutralize_workflow_commands
from aibom_scanner.models import ScanResult

SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _slug(title: str) -> str:
    """ASCII slug of a risk title: lowercase, runs of non-alphanumerics become one '-'."""
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "risk"


def _line(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else 1


def _location_records(result: ScanResult) -> list[tuple[str, int, str]]:
    """(path, line, provider) for every record that names a file, in source-list order."""
    out: list[tuple[str, int, str]] = []
    for d in result.detections:
        out.append((d.get("file_path") or "", _line(d.get("line_number")), d.get("provider", "")))
    for d in result.dependencies:
        out.append((d.get("source_file") or "", 1, d.get("provider", "")))
    for s in result.mcp_servers:
        out.append((s.get("file") or "", _line(s.get("line")), "mcp"))
    for t in result.tool_capabilities:
        out.append((t.get("file") or "", _line(t.get("line")), ""))
    for s in result.secrets:
        out.append((s.get("file_path") or "", 1, ""))
    return [(p.replace("\\", "/").removeprefix("./"), n, prov) for p, n, prov in out if p]


def _risk_location(risk: dict, records: list[tuple[str, int, str]]) -> dict:
    """Pick the SARIF location for a risk, deterministically.

    GitHub code scanning rejects results without a location. Prefer the first record
    (sorted by path, then line) whose provider the risk names; else the first record of
    any kind. Observed risks are built from detections, dependencies, MCP servers, tool
    capabilities or secrets, so a record exists for every one of them; the "." fallback
    is for hand-built results only.
    """
    providers = set(risk.get("affected_providers", []))
    pool = [r for r in records if r[2] in providers] or records
    path, line, _ = min(pool, key=lambda r: (r[0], r[1])) if pool else (".", 1, "")
    return {"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}


def format_sarif(result: ScanResult) -> str:
    """Format scan result as SARIF v2.1.0 JSON."""
    rules = []
    results = []
    rule_ids_seen = set()
    records = _location_records(result)

    for risk in result.risks:
        # Inferred findings are governance checklist items, not defects at a code
        # location. Emitting them as code-scanning alerts is a false positive.
        if risk.get("evidence_basis", "observed") == "inferred":
            continue

        rule_id = f"aibom/{risk.get('category', 'unknown')}/{_slug(risk.get('title', ''))}"
        severity = risk.get("severity", "medium")

        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": risk.get("title", "")},
                "fullDescription": {"text": risk.get("remediation", "")},
                "defaultConfiguration": {
                    "level": SARIF_LEVEL_MAP.get(severity, "warning"),
                },
                "properties": {
                    "tags": risk.get("framework_refs", []),
                },
            })

        # Create a result for each affected detection
        providers = risk.get("affected_providers", [])
        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL_MAP.get(severity, "warning"),
            "message": {
                "text": f"{risk.get('title', '')}. Providers: {', '.join(providers)}. {risk.get('remediation', '')}",
            },
            "locations": [_risk_location(risk, records)],
        })

    coverage = asdict(result.coverage) if result.coverage else None
    inferred_count = sum(
        1 for r in result.risks if r.get("evidence_basis", "observed") == "inferred"
    )

    invocation = {
        "executionSuccessful": True,
        "properties": {
            "coverage": coverage,
            "inferredFindingsExcluded": inferred_count,
        },
    }

    notifications = []
    if coverage and coverage["unsupported_languages"]:
        detail = ", ".join(
            f"{coverage['unscanned_by_extension'].get(ext, 0)} {ext} files"
            for ext in coverage["unsupported_languages"]
        )
        notifications.append({
            "level": "warning",
            "message": {
                "text": (
                    f"Incomplete coverage: {detail} could not be read by aibom-scanner "
                    f"{__version__}. This run scanned {coverage['files_scanned']} of "
                    f"{coverage['source_files_seen']} source files "
                    f"({coverage['coverage_pct']}%). Results are partial, not clean."
                ),
            },
        })
    if coverage and coverage.get("unread_source_files"):
        detail = ", ".join(f"{n} {ext} files" for ext, n in sorted(coverage["unread_source_files"].items()))
        notifications.append({
            "level": "warning",
            "message": {
                "text": (
                    f"Incomplete coverage: {detail} were not read (too large or unreadable). "
                    f"This run scanned {coverage['files_scanned']} of {coverage['source_files_seen']} "
                    f"source files ({coverage['coverage_pct']}%). Results are partial, not clean."
                ),
            },
        })
    if coverage and coverage.get("incomplete_inputs"):
        detail = ", ".join(f"{r}: {n}" for r, n in sorted(coverage["incomplete_inputs"].items()))
        total = sum(coverage["incomplete_inputs"].values())
        notifications.append({
            "level": "warning",
            "message": {
                "text": (
                    f"Incomplete coverage: {total} inputs were not fully analysed ({detail}). "
                    f"This run scanned {coverage['files_scanned']} of {coverage['source_files_seen']} "
                    f"source files ({coverage['coverage_pct']}%). Results are partial, not clean."
                ),
            },
        })
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aibom-scanner",
                        "version": __version__,
                        "informationUri": "https://github.com/saasvista/aibom-scanner",
                        "rules": rules,
                    },
                },
                "invocations": [invocation],
                "properties": {"coverage": coverage},
                "results": results,
            },
        ],
    }

    return neutralize_workflow_commands(json.dumps(sarif, indent=2))
