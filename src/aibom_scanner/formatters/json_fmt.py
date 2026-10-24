"""JSON output formatter."""

import json
import re
from dataclasses import asdict

from aibom_scanner.models import ScanResult


def neutralize_workflow_commands(text: str) -> str:
    """Rewrite each ``##[`` in JSON text as ``#\\u0023[``.

    The GitHub Actions runner parses legacy ``##[cmd]`` workflow commands anywhere in a
    log line. ``#`` only occurs inside JSON strings, where ``\\u0023`` decodes to ``#``, so
    json.loads of the result is identical to json.loads of the input.
    """
    return re.sub(r"#(?=#\[)", r"\\u0023", text)


def format_json(result: ScanResult) -> str:
    """Format scan result as indented JSON."""
    return neutralize_workflow_commands(json.dumps(asdict(result), indent=2, default=str))
