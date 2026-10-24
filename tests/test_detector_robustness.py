"""R1 (RecursionError no longer empties a file), M1 (linear key-line map), M2 (bad URL in transport guess)."""

import json
import time

import pytest

from aibom_scanner.detectors.mcp_servers import scan_mcp_config, scan_mcp_json, scan_mcp_python
from aibom_scanner.detectors.tool_capabilities import scan_tool_imports


class TestRecursionR1:
    def test_long_attribute_chain_keeps_capability(self):
        src = (
            "from langchain_community.tools import ShellTool\n"
            "import tavily\n"
            "tools = [ShellTool()]\n"
            "z = tavily" + ".b" * 3000 + "\n"
        )
        tools = scan_tool_imports("agent.py", src)
        assert any("ShellTool" in t["tool"] and "code_execution" in t["classes"] for t in tools)

    def test_scan_tool_imports_raises_on_deep_parse(self):
        src = "import tavily\nx = a" + ".b" * 100_000 + "\n"
        with pytest.raises(RecursionError):
            scan_tool_imports("agent.py", src)

    def test_scan_mcp_python_raises_on_deep_parse(self):
        src = "from mcp import StdioServerParameters\nx = a" + ".b" * 100_000 + "\n"
        with pytest.raises(RecursionError):
            scan_mcp_python("srv.py", src)

    def test_scan_mcp_python_attaches_partial_servers(self):
        src = (
            "from mcp import StdioServerParameters\n"
            "fs = StdioServerParameters(command='npx', args=['-y', 'pkg'])\n"
            "z = fs" + ".b" * 3000 + "\n"
        )
        with pytest.raises(RecursionError) as exc:
            scan_mcp_python("srv.py", src)
        assert [s["command"] for s in exc.value.partial] == ["npx"]

    def test_scan_mcp_config_raises_on_deep_json(self):
        depth = 100_000
        with pytest.raises(RecursionError):
            scan_mcp_config(".mcp.json", '{"mcpServers": ' + "[" * depth + "]" * depth + "}")

    def test_syntax_error_still_yields_empty(self):
        assert scan_tool_imports("a.py", "import tavily\nx = (\n") == []
        assert scan_mcp_python("a.py", "from mcp import StdioServerParameters\nx = (\n") == []
        assert scan_mcp_config(".mcp.json", "{not json") == []
