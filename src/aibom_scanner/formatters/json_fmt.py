"""JSON output formatter."""

import json
from dataclasses import asdict

from aibom_scanner.models import ScanResult


def format_json(result: ScanResult) -> str:
    """Format scan result as indented JSON."""
    return json.dumps(asdict(result), indent=2, default=str)
