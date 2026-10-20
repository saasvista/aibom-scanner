"""Tests for the per-server MCP inventory."""

import json

import pytest

from aibom_scanner.detectors.mcp_servers import (
    compute_pinned,
    redact_args,
    scan_mcp_config,
    scan_mcp_python,
    url_host,
)
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.risk_engine import classify_risks, consolidate_risks
from aibom_scanner.scanner import scan_directory

FAKE = "FAKE-NOT-A-KEY-123456"

CONFIG = {
    "mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/data"]},
        "remote": {
            "url": f"https://user:{FAKE}@mcp.example.com/v1/mcp?token={FAKE}",
            "type": "sse",
            "headers": {"Authorization": f"Bearer {FAKE}"},
        },
    }
}


def _write_config(root, rel, data):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


class TestConfigFiles:
    @pytest.mark.parametrize(
        "rel", ["mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json",
                ".cursor/mcp.json", ".vscode/mcp.json"],
    )
    def test_each_filename(self, tmp_path, rel):
        _write_config(tmp_path, rel, CONFIG)
        servers = scan_directory(tmp_path).mcp_servers
        assert {s["name"] for s in servers} == {"files", "remote"}
        assert all(s["source"] == "config" and s["file"] == rel for s in servers)

    def test_servers_key(self, tmp_path):
        _write_config(tmp_path, ".vscode/mcp.json", {"servers": {"a": {"command": "uvx", "args": ["tool==1.0"]}}})
        (server,) = scan_directory(tmp_path).mcp_servers
        assert (server["name"], server["transport"], server["pinned"]) == ("a", "stdio", True)

    def test_fields(self):
        files, remote = scan_mcp_config(".mcp.json", json.dumps(CONFIG))
        assert files["transport"] == "stdio" and files["command"] == "npx" and files["pinned"] is True
        assert remote["transport"] == "sse" and remote["url_host"] == "https://mcp.example.com"
        assert remote["header_keys"] == ["Authorization"] and remote["pinned"] is None
        assert files["line"] > 0

    def test_env_keys_only(self):
        cfg = {"mcpServers": {"s": {"command": "x", "env": {"API_TOKEN": FAKE, "OTHER": "v"}}}}
        (server,) = scan_mcp_config("mcp.json", json.dumps(cfg))
        assert server["env_keys"] == ["API_TOKEN", "OTHER"]

    def test_malformed_json_does_not_crash(self, tmp_path):
        (tmp_path / ".mcp.json").write_text('{"mcpServers": {"a": ')
        (tmp_path / "mcp.json").write_text("[1, 2]")
        (tmp_path / "mcp_config.json").write_text('{"mcpServers": {"a": "not a dict", "b": null}}')
        assert scan_directory(tmp_path).mcp_servers == []


class TestContentBasedConfig:
    def test_any_json_with_mcpservers_key(self, tmp_path):
        _write_config(tmp_path, "extensions_config.example.json", {"mcpServers": {"a": {"command": "x"}}, "skills": {}})
        (s,) = scan_directory(tmp_path).mcp_servers
        assert (s["name"], s["file"]) == ("a", "extensions_config.example.json")

    def test_servers_key_only_read_for_named_files(self, tmp_path):
        _write_config(tmp_path, "other.json", {"servers": {"a": {"command": "x"}}})
        _write_config(tmp_path, "unrelated.json", {"mcpServers": {"a": {}}, "servers": {"b": {"command": "y"}}})
        assert [s["name"] for s in scan_directory(tmp_path).mcp_servers] == ["a"]

    def test_large_json_is_skipped(self, tmp_path):
        _write_config(tmp_path, "big.json", {"mcpServers": {"a": {"command": "x"}}, "pad": "x" * 1_100_000})
        assert scan_directory(tmp_path).mcp_servers == []


class TestPythonConstructors:
    def test_mcp_stdio_server_parameters(self):
        src = (
            "from mcp import StdioServerParameters\n"
            f"fs = StdioServerParameters(command='npx', args=['-y', 'pkg@1.0.0'], env={{'API_TOKEN': '{FAKE}'}})\n"
        )
        (s,) = scan_mcp_python("app.py", src)
        assert (s["name"], s["transport"], s["framework"], s["line"]) == ("fs", "stdio", "mcp", 2)
        assert s["env_keys"] == ["API_TOKEN"] and s["pinned"] is True and s["source"] == "code"

    def test_langchain_multiserver_config_dict(self):
        src = (
            "from langchain_mcp_adapters.client import MultiServerMCPClient\n"
            "client = MultiServerMCPClient({\n"
            "  'math': {'command': 'python', 'args': ['math.py'], 'transport': 'stdio'},\n"
            "  'web': {'url': 'http://localhost:8000/mcp', 'transport': 'streamable_http'},\n"
            "})\n"
        )
        math, web = scan_mcp_python("a.py", src)
        assert (math["name"], math["transport"], math["framework"]) == ("math", "stdio", "langgraph")
        assert (web["name"], web["transport"], web["url_host"]) == ("web", "http", "http://localhost:8000")

    def test_langchain_connect_to_server(self):
        src = (
            "from langchain_mcp_adapters.client import MultiServerMCPClient\n"
            "async def main():\n"
            "    async with MultiServerMCPClient() as client:\n"
            "        await client.connect_to_server('weather', command='uvx', args=['wx'], transport='stdio')\n"
        )
        (s,) = scan_mcp_python("a.py", src)
        assert (s["name"], s["command"], s["pinned"]) == ("weather", "uvx", False)

    def test_openai_agents_family(self):
        src = (
            "from agents.mcp import MCPServerStdio, MCPServerSse, MCPServerStreamableHttp\n"
            "from agents import HostedMCPTool\n"
            "a = MCPServerStdio(name='fs', params={'command': 'npx', 'args': ['-y', 'x']})\n"
            "b = MCPServerSse(name='sse', params={'url': 'https://h.example/sse', 'headers': {'X-Key': 'v'}})\n"
            "c = MCPServerStreamableHttp(params={'url': 'https://h2.example/mcp'})\n"
            "d = HostedMCPTool(tool_config={'type': 'mcp', 'server_label': 'gitmcp', 'server_url': 'https://g.io/x'})\n"
        )
        a, b, c, d = scan_mcp_python("a.py", src)
        assert (a["transport"], a["command"], a["pinned"]) == ("stdio", "npx", False)
        assert (b["transport"], b["url_host"], b["header_keys"]) == ("sse", "https://h.example", ["X-Key"])
        assert (c["transport"], c["name"]) == ("http", "c")
        assert (d["transport"], d["name"], d["url_host"]) == ("hosted", "gitmcp", "https://g.io")
        assert {s["framework"] for s in (a, b, c, d)} == {"openai_agents"}

    def test_autogen_family(self):
        src = (
            "from autogen_ext.tools.mcp import StdioServerParams, SseServerParams, StreamableHttpServerParams\n"
            "p1 = StdioServerParams(command='uvx', args=['t==1.0'])\n"
            "p2 = SseServerParams(url='https://a.example/sse', headers={'Auth': 'x'})\n"
            "p3 = StreamableHttpServerParams(url='https://b.example/mcp')\n"
        )
        s1, s2, s3 = scan_mcp_python("a.py", src)
        assert [s["transport"] for s in (s1, s2, s3)] == ["stdio", "sse", "http"]
        assert s1["pinned"] is True and s2["header_keys"] == ["Auth"]
        assert {s["framework"] for s in (s1, s2, s3)} == {"autogen"}

    def test_crewai_stdio_and_adapter_dict(self):
        src = (
            "from crewai import Agent\n"
            "from crewai_tools import MCPServerAdapter\n"
            "from mcp import StdioServerParameters\n"
            "p = StdioServerParameters(command='python', args=['srv.py'])\n"
            "cfg = {'url': 'http://localhost:8001/sse', 'transport': 'sse'}\n"
            "with MCPServerAdapter(cfg) as tools:\n"
            "    pass\n"
        )
        stdio, adapter = scan_mcp_python("a.py", src)
        assert (stdio["framework"], stdio["transport"]) == ("crewai", "stdio")
        assert (adapter["framework"], adapter["transport"]) == ("crewai", "sse")
        assert adapter["url_host"] == "http://localhost:8001"

    def test_import_aliases(self):
        src = (
            "import mcp as m\n"
            "import agents.mcp as am\n"
            "from autogen_ext.tools.mcp import StdioServerParams as SP\n"
            "x = m.StdioServerParameters(command='a')\n"
            "y = am.MCPServerStdio(params={'command': 'b'})\n"
            "z = SP(command='c')\n"
        )
        assert [s["command"] for s in scan_mcp_python("a.py", src)] == ["a", "b", "c"]

    def test_unrelated_constructor_ignored(self):
        src = "class StdioServerParameters: pass\nx = StdioServerParameters(command='a')\n"
        assert scan_mcp_python("a.py", src) == []

    def test_unparseable_python_is_skipped(self, tmp_path):
        (tmp_path / "bad.py").write_text("from mcp import StdioServerParameters\nx = StdioServerParameters(command=\n")
        (tmp_path / "ok.py").write_text(
            "from mcp import StdioServerParameters\nx = StdioServerParameters(command='a')\n"
        )
        assert [s["file"] for s in scan_directory(tmp_path).mcp_servers] == ["ok.py"]


class TestRedaction:
    def test_probe_cases(self):
        assert redact_args(["-y", "some-mcp", "-H", f"X-Api-Key: {FAKE}"], "npx") == ["-y", "some-mcp", "-H", "<arg>"]
        assert redact_args(["tool", f"API_TOKEN={FAKE}"], "uvx") == ["tool", "<arg>"]
        assert redact_args(["server.js", "q9Zx7Lm2Pp4Rt8Vw1Yb6Nc3Kd5Hf0Jg"], "node") == ["<arg>", "<arg>"]
        assert redact_args(["-c", f"TOKEN={FAKE} npx thing"], "sh") == ["-c", "<arg>"]

    @pytest.mark.parametrize(
        "command,args,expected",
        [
            ("npx", ["--api-key", "PROBELEAK18", "some-pkg"], ["--api-key", "<arg>", "<arg>"]),
            ("uvx", ["--token", "PROBELEAK19", "tool"], ["--token", "<arg>", "<arg>"]),
            ("docker", ["run", "--secret-thing", "PROBELEAK20", "img:1"],
             ["run", "--secret-thing", "<arg>", "<arg>"]),
            ("pipx", ["run", "--x", "PROBELEAK22", "pkg"], ["run", "--x", "<arg>", "<arg>"]),
        ],
    )
    def test_unknown_flag_before_the_package_means_no_spec(self, command, args, expected):
        assert redact_args(args, command) == expected
        assert compute_pinned(command, args) is None

    def test_spec_position_rejects_key_value_and_credentialed_urls(self):
        assert redact_args([f"API_TOKEN={FAKE}", "tool"], "uvx") == ["<arg>", "<arg>"]
        assert redact_args([f"tool=={FAKE}=x"], "uvx") == ["<arg>"]
        assert redact_args(["tool==1.0"], "uvx") == ["tool==1.0"]
        assert url_host(f"{FAKE}://h.example/x") is None
        cfg = {"mcpServers": {"s": {"command": f"https://u:{FAKE}@h.example/x", "args": []}}}
        (s,) = scan_mcp_config("mcp.json", json.dumps(cfg))
        assert s["command"] == "<redacted>" and FAKE not in json.dumps(s)

    def test_no_spec_means_unknown(self):
        assert compute_pinned("npx", ["--api-key", "v"]) is None
        assert redact_args(["--api-key", "v"], "npx") == ["--api-key", "<arg>"]

    def test_flag_value_forms(self):
        out = redact_args(["--api-key=" + FAKE, "--port", "80", "--bad flag=" + FAKE, "--x=a=b"], "node")
        assert out == ["--api-key=<redacted>", "--port", "<arg>", "<arg>", "--x=<redacted>"]

    def test_docker_args(self):
        args = ["run", "-i", "--rm", "-e", f"K={FAKE}", "--env", "bad-name=" + FAKE, "ghcr.io/o/img:1.4", "serve"]
        assert redact_args(args, "docker") == [
            "run", "-i", "--rm", "-e", "K=<redacted>", "--env", "<arg>", "ghcr.io/o/img:1.4", "<arg>"]

    def test_spec_with_url_is_reduced(self):
        assert redact_args([f"https://u:{FAKE}@h.example/p?q=1"], "npx") == ["https://h.example"]
        assert redact_args(["bad spec " + FAKE], "npx") == ["<arg>"]

    def test_unsafe_command_is_redacted(self):
        cfg = {"mcpServers": {"s": {"command": f"API_KEY={FAKE} npx thing", "args": ["-y", "pkg@1.0"]}}}
        (s,) = scan_mcp_config("mcp.json", json.dumps(cfg))
        assert s["command"] == "<redacted>" and s["pinned"] is None and s["args"] == ["-y", "<arg>"]
        assert FAKE not in json.dumps(s)

    def test_dynamic_args(self):
        src = "from mcp import StdioServerParameters\nx = StdioServerParameters(command='node', args=[p, 'a'])\n"
        (s,) = scan_mcp_python("a.py", src)
        assert s["args"] == ["<dynamic>", "<arg>"]

    def test_url_host(self):
        assert url_host(f"https://u:{FAKE}@h.example:8443/a?t={FAKE}") == "https://h.example:8443"
        assert url_host("${MCP_URL}") is None and url_host(None) is None

    def test_full_scan_never_outputs_a_value(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", {"mcpServers": {
            "remote": {"url": f"https://mcp.example.com/x?token={FAKE}", "headers": {"X-Api-Key": FAKE}},
            "local": {"command": "node", "args": ["srv.js", "--token", FAKE, f"--secret={FAKE}"],
                      "env": {"MY_SECRET": FAKE}},
            "p1": {"command": "npx", "args": ["-y", "some-mcp", "-H", f"X-Api-Key: {FAKE}"]},
            "p2": {"command": "uvx", "args": ["tool", f"API_TOKEN={FAKE}"]},
            "p3": {"command": "node", "args": ["server.js", "q9Zx7Lm2Pp4Rt8Vw1Yb6Nc3Kd5Hf0Jg" + FAKE]},
            "p4": {"command": "sh", "args": ["-c", f"TOKEN={FAKE} npx thing"]},
            "p5": {"command": "npx", "args": ["pkg", f"--auth={FAKE}", f"https://u:{FAKE}@h.example/p?q=1"]},
            "p8": {"command": "npx", "args": ["--api-key", FAKE, "some-pkg"]},
            "p9": {"command": "uvx", "args": ["--token", FAKE, "tool"]},
            "p10": {"command": "docker", "args": ["run", "--secret-thing", FAKE, "img:1"]},
            "p11": {"command": "pipx", "args": ["run", "--x", FAKE, "pkg"]},
            "p6": {"command": f"KEY={FAKE} npx", "args": ["x"]},
            "p7": {"command": "docker", "args": ["run", "-e", f"DB_PASS={FAKE}", "--env", f"T={FAKE}", "img:1"]},
        }})
        (tmp_path / "agent.py").write_text(
            "from mcp import StdioServerParameters\n"
            f"s = StdioServerParameters(command='node', args=['x.js', '--password', '{FAKE}'], "
            f"env={{'DB_PASS': '{FAKE}'}})\n"
            "from agents.mcp import MCPServerSse\n"
            f"t = MCPServerSse(params={{'url': 'https://h.example/sse?k={FAKE}', "
            f"'headers': {{'Authorization': '{FAKE}'}}}})\n"
        )
        result = scan_directory(tmp_path)
        assert len(result.mcp_servers) == 15
        for output in (format_json(result), format_sarif(result), format_table(result)):
            assert FAKE not in output
        data = json.loads(format_json(result))
        assert {k for s in data["mcp_servers"] for k in s["env_keys"]} == {"MY_SECRET", "DB_PASS", "T"}
        assert {k for s in data["mcp_servers"] for k in s["header_keys"]} == {"X-Api-Key", "Authorization"}


class TestPinned:
    @pytest.mark.parametrize(
        "command,args,expected",
        [
            ("npx", ["-y", "pkg@1.2.3"], True),
            ("npx", ["-y", "@scope/pkg@1.2.3"], True),
            ("npx", ["-y", "pkg"], False),
            ("npx", ["-y", "@scope/pkg"], False),
            ("npx", ["pkg@latest"], False),
            ("uvx", ["pkg==1.2.3"], True),
            ("uvx", ["pkg"], False),
            ("uvx", ["--from", "pkg==2.0", "cmd"], True),
            ("pipx", ["run", "pkg==1.0"], True),
            ("pipx", ["run", "pkg"], False),
            ("pipx", ["install", "pkg"], None),
            ("docker", ["run", "-i", "--rm", "-e", "K", "ghcr.io/o/img:1.4"], True),
            ("docker", ["run", "-i", "ghcr.io/o/img:latest"], False),
            ("docker", ["run", "-i", "ghcr.io/o/img"], False),
            ("docker", ["run", "img@sha256:" + "a" * 64], True),
            ("docker", ["run", "-p", "5000:80", "localhost:5000/img"], None),
            ("docker", ["run", "-i", "--rm", "my-mcp-server"], None),
            ("docker", ["run", "-i", "--rm", "my-mcp-server:dev"], None),
            ("docker", ["run", "-i", "--rm", "mcp/github"], False),
            ("npx", ["tsx", "./server.ts"], None),
            ("npx", ["-y", "tsx@4.19.0", "src/server.ts"], None),
            ("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/data"], False),
            ("node", ["server.js"], None),
            ("npx", ["-y", "<dynamic>"], None),
        ],
    )
    def test_pinned(self, command, args, expected):
        assert compute_pinned(command, args) is expected

    def test_url_transport_is_null(self):
        (s,) = scan_mcp_config("mcp.json", json.dumps({"mcpServers": {"r": {"url": "https://h.example/mcp"}}}))
        assert s["pinned"] is None


class TestRiskEvidence:
    def test_rule_carries_per_server_evidence(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", CONFIG)
        (tmp_path / "srv.py").write_text("import mcp\nfrom mcp import StdioServerParameters\n"
                                         "s = StdioServerParameters(command='x')\n")
        result = scan_directory(tmp_path)
        risk = next(r for r in result.risks if r["title"] == "Agentic AI framework without human oversight controls")
        assert any("files (stdio) .mcp.json:" in e for e in risk["evidence"])
        assert any("s (stdio) srv.py:3" in e for e in risk["evidence"])
        assert risk["evidence_basis"] == "observed"

    def test_config_only_repo_gets_mcp_risk(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", CONFIG)
        result = scan_directory(tmp_path)
        risk = next(r for r in result.risks if r["title"] == "Agentic AI framework without human oversight controls")
        assert any(e.startswith("files (stdio) .mcp.json:") for e in risk["evidence"])
        assert risk["evidence_basis"] == "observed"
        assert result.detections == [] and "mcp" not in result.summary["providers"]

    def test_rule_unchanged_with_import_only(self):
        risks = consolidate_risks(classify_risks(["mcp"]))
        risk = next(r for r in risks if r["title"] == "Agentic AI framework without human oversight controls")
        assert "evidence" not in risk

    def test_standalone_rule_evidence(self):
        servers = [{"name": "a", "transport": "stdio", "file": "mcp.json", "line": 4}]
        risk = next(r for r in classify_risks(["mcp"], mcp_servers=servers)
                    if r["title"] == "MCP server exposes tools without governance controls")
        assert risk["evidence"] == ["a (stdio) mcp.json:4"]


class TestOutput:
    def test_json_has_servers_and_note(self, tmp_path):
        _write_config(tmp_path, "mcp.json", CONFIG)
        data = json.loads(format_json(scan_directory(tmp_path)))
        assert len(data["mcp_servers"]) == 2
        assert data["summary"]["total_mcp_servers"] == 2
        assert "C#, TypeScript or Go" in data["summary"]["mcp_servers_note"]

    def test_table_section_only_with_servers(self, tmp_path):
        assert "MCP Servers" not in format_table(scan_directory(tmp_path))
        _write_config(tmp_path, "mcp.json", CONFIG)
        assert "MCP Servers (2)" in format_table(scan_directory(tmp_path))

    def test_empty_repo(self, empty_repo):
        assert scan_directory(empty_repo).mcp_servers == []


class TestConfigOnlyRepo:
    """MCP found only through config is a synthetic provider: provider-wide rules must not fire."""

    def _config_repo(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", {"mcpServers": {
            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"]},
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        }})
        (tmp_path / "main.go").write_text("package main\n")

    def test_config_only_titles(self, tmp_path):
        self._config_repo(tmp_path)
        titles = {r["title"] for r in scan_directory(tmp_path).risks}
        assert titles == {
            "Agentic AI framework without human oversight controls",
            "Codebase combines untrusted input, sensitive data access and an action capability",
            "MCP server launched without a pinned version",
        }

    def test_config_only_keeps_server_evidence(self, tmp_path):
        self._config_repo(tmp_path)
        risks = scan_directory(tmp_path).risks
        text = json.dumps(risks)
        assert ".mcp.json" in text

    def test_real_sdk_detection_unchanged(self, tmp_path):
        self._config_repo(tmp_path)
        (tmp_path / "app.py").write_text("import mcp\n")
        titles = {r["title"] for r in scan_directory(tmp_path).risks}
        assert "AI model usage without governance framework" in titles
        assert "API keys potentially exposed in source code" in titles


class TestFailClosedSpec:
    """An unknown flag before the candidate package means there is no spec: never emit a secret positional."""

    SHAPES = [
        ("npx", ["--prefer-offline", "@x/server", FAKE]),
        ("docker", ["run", "-ti", "img:1", FAKE]),
        ("uvx", ["--refresh", "pkg", FAKE]),
    ]

    @pytest.mark.parametrize("command,args", SHAPES)
    def test_redact_and_pinned(self, command, args):
        out = redact_args(args, command)
        assert FAKE not in json.dumps(out) and "@x/server" not in out and "img:1" not in out and "pkg" not in out
        assert compute_pinned(command, args) is None

    def test_config_and_formatters(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", {"mcpServers": {
            f"s{i}": {"command": c, "args": a} for i, (c, a) in enumerate(self.SHAPES)}})
        result = scan_directory(tmp_path)
        assert len(result.mcp_servers) == 3
        assert all(s["pinned"] is None for s in result.mcp_servers)
        for output in (json.dumps(result.mcp_servers), json.dumps(result.risks),
                       format_json(result), format_sarif(result), format_table(result)):
            assert FAKE not in output

    def test_python_constructor(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "from mcp import StdioServerParameters\n"
            f"s = StdioServerParameters(command='npx', args=['--prefer-offline', '@x/server', '{FAKE}'])\n"
        )
        result = scan_directory(tmp_path)
        (srv,) = result.mcp_servers
        assert srv["pinned"] is None and srv["args"] == ["--prefer-offline", "<arg>", "<arg>"]
        for output in (json.dumps(result.mcp_servers), format_json(result), format_sarif(result), format_table(result)):
            assert FAKE not in output

    @pytest.mark.parametrize(
        "command,args,spec,pinned",
        [
            ("npx", ["-y", "pkg@1.2.3"], "pkg@1.2.3", True),
            ("uvx", ["pkg"], "pkg", False),
            ("docker", ["run", "-i", "--rm", "org/image:tag"], "org/image:tag", True),
            ("docker", ["run", "-e", "K=v", "-v", "/a:/b", "org/image:tag"], "org/image:tag", True),
        ],
    )
    def test_known_forms_still_resolve(self, command, args, spec, pinned):
        assert spec in redact_args(args, command)
        assert compute_pinned(command, args) is pinned


class TestOddInput:
    """Hostile or odd input must never crash a scan."""

    def test_non_string_args(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", {"mcpServers": {
            "a": {"command": "npx", "args": [["-y"], "pkg"]},
            "b": {"command": "docker", "args": ["run", {"x": 1}, "img:1"], "env": ["x"], "headers": 3},
            "c": {"command": ["npx"], "url": ["u"], "args": [None, 5]},
        }})
        result = scan_directory(tmp_path)
        assert len(result.mcp_servers) == 3
        assert result.mcp_servers[0]["args"][0] == "<dynamic>"

    def test_deeply_nested_json(self, tmp_path):
        depth = 100_000
        (tmp_path / "deep.json").write_text('{"mcpServers": ' + "[" * depth + "]" * depth + "}")
        assert scan_directory(tmp_path).mcp_servers == []

    @pytest.mark.parametrize("expr", [
        " + ".join(["'a'"] * 500),
        "x" + ".m()" * 200,
    ], ids=["plus_chain", "call_chain"])
    def test_deep_expression_in_mcp_python(self, tmp_path, expr):
        (tmp_path / "app.py").write_text(
            "from mcp import StdioServerParameters\n"
            "s = StdioServerParameters(command='uvx', args=['t'])\n"
            f"y = {expr}\n"
        )
        assert scan_directory(tmp_path).summary["files_scanned"] >= 1

    def test_deep_attribute_chain(self, tmp_path):
        (tmp_path / "app.py").write_text("import langchain_community\nx = a" + ".b" * 1000 + "\n")
        assert scan_directory(tmp_path).summary["files_scanned"] >= 1


class TestConfigEvidenceCap:
    """Config-file evidence alone never reaches HIGH."""

    RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    UNTRUSTED = "from crewai_tools import BraveSearchTool\n"
    SENSITIVE = "from langchain_community.agent_toolkits.sql.toolkit import SQLDatabaseToolkit\n"
    ACTION = "from langchain_community.tools.ifttt import IFTTTWebhook\n"

    def _config_repo(self, tmp_path):
        _write_config(tmp_path, ".mcp.json", {"mcpServers": {
            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/home/x"]},
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        }})
        (tmp_path / "main.go").write_text("package main\n")

    def _combined(self, result):
        return [r for r in result.risks if r["title"].startswith("Codebase combines")]

    def test_config_only_repo_is_medium_at_most_and_exits_zero(self, tmp_path):
        from aibom_scanner.cli import main
        self._config_repo(tmp_path)
        risks = scan_directory(tmp_path).risks
        assert risks and all(self.RANK[r["severity"]] <= 2 for r in risks)
        assert all(r["evidence_qualifier"] for r in risks if r["severity"] == "medium" and r["title"].startswith("Agentic"))
        try:
            main(["scan", "--path", str(tmp_path), "--severity-threshold", "high"])
        except SystemExit as exc:
            assert exc.code in (0, None)

    def test_python_file_with_three_legs_is_still_high(self, tmp_path):
        (tmp_path / "agent.py").write_text(self.UNTRUSTED + self.SENSITIVE + self.ACTION)
        (finding,) = self._combined(scan_directory(tmp_path))
        assert finding["severity"] == "high" and finding["evidence_qualifier"] == ""

    def test_sdk_plus_config_gets_mcp_config_medium_and_other_findings_unchanged(self, tmp_path):
        (tmp_path / "app.py").write_text("import mcp\n")
        sdk_only = {(r["title"], r["severity"]) for r in scan_directory(tmp_path).risks}
        self._config_repo(tmp_path)
        result = scan_directory(tmp_path)
        (finding,) = self._combined(result)
        assert finding["severity"] == "medium" and finding["evidence_qualifier"] == "mcp_config"
        assert "availability, not use" in " ".join(finding["evidence"])
        both = {(r["title"], r["severity"]) for r in result.risks}
        assert sdk_only <= both
        assert not any(r["evidence_qualifier"] == "mcp_config_only" for r in result.risks)
