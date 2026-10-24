"""F7: scanned-origin strings are escaped in table output."""

import json

from aibom_scanner.cli import main
from aibom_scanner.scanner import scan_directory
from aibom_scanner.formatters.table_fmt import format_table


def _table(path):
    return format_table(scan_directory(path))


def test_mcp_server_names_are_escaped(tmp_path):
    servers = {
        "\x1b[30A\x1b[J": {"command": "npx", "args": ["-y", "pkg@1.0.0"]},
        "\n::error::fake": {"command": "npx", "args": ["-y", "pkg@1.0.0"]},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}))
    out = _table(tmp_path)
    assert "\x1b[30A" not in out and "\x1b[J" not in out
    assert not any(line.lstrip().startswith("::error::") or line.startswith("::error::") for line in out.split("\n"))
    assert "\\x1b" in out
    assert "\\x0a" in out


def test_filename_with_osc_is_escaped(tmp_path):
    (tmp_path / "a\x1b]0;T\x07.py").write_text("import openai\n")
    out = _table(tmp_path)
    assert "\x07" not in out
    assert "\x1b]0" not in out
    assert "\\x1b" in out or "\\x07" in out
    assert "openai" in out


def test_cli_table_path(tmp_path, capsys):
    (tmp_path / "a\x1b]0;T\x07.py").write_text("import openai\n")
    main(["scan", "--path", str(tmp_path), "--format", "table"])
    assert "\x07" not in capsys.readouterr().out
