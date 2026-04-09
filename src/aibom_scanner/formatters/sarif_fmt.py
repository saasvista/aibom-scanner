"""SARIF v2.1.0 output for GitHub Code Scanning integration."""

import json

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
                "results": results,
            },
        ],
    }

    return json.dumps(sarif, indent=2)
