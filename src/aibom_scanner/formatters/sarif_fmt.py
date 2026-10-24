"""SARIF v2.1.0 output for GitHub Code Scanning integration."""

import json
from dataclasses import asdict

from aibom_scanner import __version__
from aibom_scanner.models import ScanResult

SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def format_sarif(result: ScanResult) -> str:
    """Format scan result as SARIF v2.1.0 JSON."""
    rules = []
    results = []
    rule_ids_seen = set()

    for i, risk in enumerate(result.risks):
        # Inferred findings are governance checklist items, not defects at a code
        # location. Emitting them as code-scanning alerts is a false positive.
        if risk.get("evidence_basis", "observed") == "inferred":
            continue

        rule_id = f"aibom/{risk.get('category', 'unknown')}/{i}"
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

    return json.dumps(sarif, indent=2)
