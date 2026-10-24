"""Audit F8: MCP server line lookup must be linear."""

import json
import time

from aibom_scanner.detectors.mcp_servers import scan_mcp_json

class TestMcpLineLookup:
    def test_large_config_is_linear(self):
        content = json.dumps({"mcpServers": {f"s{i}": {} for i in range(32000)}})
        t = time.perf_counter()
        servers = scan_mcp_json("mcp.json", content)
        assert time.perf_counter() - t < 2
        assert len(servers) == 32000

    def test_line_numbers_small_config(self):
        content = (
            "{\n"
            '  "mcpServers": {\n'
            '    "alpha": {"command": "a"},\n'
            '    "beta": {\n'
            '      "command": "b"\n'
            "    },\n"
            '    "gamma": {"url": "https://example.com/mcp"}\n'
            "  }\n"
            "}\n"
        )
        lines = {s["name"]: s["line"] for s in scan_mcp_json("mcp.json", content)}
        assert lines == {"alpha": 3, "beta": 4, "gamma": 7}
