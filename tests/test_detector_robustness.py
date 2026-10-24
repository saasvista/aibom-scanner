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
            "z = tavily" + ".b" * 1500 + "\n"
        )
        tools = scan_tool_imports("agent.py", src)
        assert any("ShellTool" in t["tool"] and "code_execution" in t["classes"] for t in tools)

    def test_long_chain_cost_is_linear(self):
        # 100k links: 3.11+ rejects this at parse (RecursionError, flagged by the scanner);
        # 3.10 parses it, and walking it must stay linear (it took minutes when every inner node was re-resolved).
        import time
        src = (
            "from langchain_community.tools import ShellTool\n"
            "tools = [ShellTool()]\n"
            "x = ShellTool" + ".b" * 100_000 + "\n"
        )
        t = time.perf_counter()
        try:
            tools = scan_tool_imports("agent.py", src)
        except RecursionError:
            return
        assert time.perf_counter() - t < 5
        assert any("ShellTool" in t["tool"] for t in tools)

    def test_scan_tool_imports_never_silently_empty_on_deep_parse(self):
        # Python 3.11+ raises RecursionError while parsing this; 3.10 parses it.
        # Either way the result must not be a silent []: the error propagates
        # (the scanner counts it as analysis_incomplete) or the tool is found.
        src = (
            "from langchain_community.tools import ShellTool\n"
            "tools = [ShellTool()]\n"
            "x = a" + ".b" * 100_000 + "\n"
        )
        try:
            tools = scan_tool_imports("agent.py", src)
        except RecursionError:
            return
        assert any("ShellTool" in t["tool"] for t in tools)

    def test_scan_mcp_python_raises_on_deep_parse(self):
        src = "from mcp import StdioServerParameters\nx = a" + ".b" * 100_000 + "\n"
        with pytest.raises(RecursionError):
            scan_mcp_python("srv.py", src)

    def test_scan_mcp_python_attaches_partial_servers(self):
        src = (
            "from mcp import StdioServerParameters\n"
            "fs = StdioServerParameters(command='npx', args=['-y', 'pkg'])\n"
            "z = fs" + ".b" * 1500 + "\n"
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


class TestKeyLineMapM1:
    def test_escaped_quote_value_is_linear(self):
        doc = '{"mcpServers":{"a":{"command":"x"}},"z":"' + '\\"' * 480_000 + '"}'
        assert len(doc) < 1_000_100
        t = time.perf_counter()
        servers = scan_mcp_json("settings.json", doc)
        assert time.perf_counter() - t < 2
        assert [(s["name"], s["line"]) for s in servers] == [("a", 1)]

    def test_lines_and_escaped_keys(self):
        doc = '{\n "mcpServers": {\n  "a\\u0062": {"command": "x"},\n  "c": {"command": "y", "env": {"k": "v:\\"w\\" : q"}}\n }\n}\n'
        lines = {s["name"]: s["line"] for s in scan_mcp_json("m.json", doc)}
        assert lines == {"ab": 3, "c": 4}

    def test_value_that_looks_like_key_not_mapped(self):
        doc = json.dumps({"x": '"a": 1', "mcpServers": {"a": {"command": "x"}}}, indent=1)
        servers = scan_mcp_json("m.json", doc)
        assert servers[0]["line"] == doc.splitlines().index('  "a": {') + 1


class TestTransportM2:
    def test_bad_ipv6_url_does_not_raise(self):
        cfg = {"mcpServers": {"x": {"url": "http://[::1/sse"}}}
        servers = scan_mcp_config(".mcp.json", json.dumps(cfg))
        assert [s["transport"] for s in servers] == ["unknown"]

    def test_good_sse_url_still_sse(self):
        cfg = {"mcpServers": {"x": {"url": "https://h.example/sse"}}}
        assert scan_mcp_config(".mcp.json", json.dumps(cfg))[0]["transport"] == "sse"
