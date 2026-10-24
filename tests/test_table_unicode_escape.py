"""T1: table output escapes Unicode control, format, separator and surrogate characters."""

import json

import pytest

from aibom_scanner.formatters.table_fmt import _safe, format_table
from aibom_scanner.scanner import scan_directory

BAD = {
    "‮": "\\u202e",
    "⁦": "\\u2066",
    "​": "\\u200b",
    "﻿": "\\ufeff",
    " ": "\\u2028",
    "\ud800": "\\ud800",
}


@pytest.mark.parametrize("ch,escaped", list(BAD.items()))
def test_safe_escapes_each_category(ch, escaped):
    assert _safe(f"a{ch}b") == f"a{escaped}b"


def test_safe_keeps_ordinary_text():
    assert _safe("naïve café 日本") == "naïve café 日本"


def test_table_has_no_raw_chars_in_mcp_name_and_scanned_path(tmp_path):
    clean = "".join(c for c in BAD if c != "\ud800")
    servers = {"srv" + "".join(BAD) + "x": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    (tmp_path / ("f" + clean + ".py")).write_text("import openai\n")
    result = scan_directory(tmp_path)
    # a lone surrogate cannot be created as a file name here; inject it in the result
    result.detections[0]["file_path"] += "\ud800"
    out = format_table(result)
    out.encode("utf-8")
    for ch in BAD:
        assert ch not in out
    assert "\\u202e" in out
