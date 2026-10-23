"""Tests for the OWASP LLM Top 10 and Agentic Top 10 control mappings and the two evidence-based findings."""

import json
import re
from pathlib import Path

import pytest

from aibom_scanner import risk_engine
from aibom_scanner.control_mapper import (
    ALL_FRAMEWORKS,
    OWASP_AGENTIC_TOP10,
    OWASP_LLM_TOP10,
    map_controls,
)
from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.models import CoverageStatus, Severity
from aibom_scanner.risk_engine import CODE_EXEC_TITLE, RISK_RULES, TRIFECTA_TITLE, UNPINNED_MCP_TITLE, classify_risks
from aibom_scanner.scanner import scan_directory

LLM = "OWASP LLM Top 10 (2025)"
ASI = "OWASP Agentic Top 10 (2026)"
# Controls no finding can reference today: there is no static signal for them.
UNREACHABLE = {
    "OWASP-LLM04", "OWASP-LLM07", "OWASP-LLM08", "OWASP-LLM09", "OWASP-LLM10",
    "OWASP-ASI06", "OWASP-ASI07", "OWASP-ASI08", "OWASP-ASI10",
}


def _all_ids():
    return {cid for table in ALL_FRAMEWORKS.values() for cid in table}


class TestTables:
    def test_both_tables_registered(self):
        assert ALL_FRAMEWORKS[LLM] is OWASP_LLM_TOP10 and ALL_FRAMEWORKS[ASI] is OWASP_AGENTIC_TOP10

    @pytest.mark.parametrize("table,prefix", [(OWASP_LLM_TOP10, "OWASP-LLM"), (OWASP_AGENTIC_TOP10, "OWASP-ASI")])
    def test_ten_unique_ids(self, table, prefix):
        assert list(table) == [f"{prefix}{i:02d}" for i in range(1, 11)]
        assert len({name for name, _ in table.values()}) == 10

    def test_titles_carry_their_id(self):
        for cid, (name, desc) in {**OWASP_LLM_TOP10, **OWASP_AGENTIC_TOP10}.items():
            assert name.startswith(cid.replace("OWASP-", "")) and desc


class TestRefsResolve:
    def _refs_in_source(self):
        text = Path(risk_engine.__file__).read_text()
        return set(re.findall(r'"((?:NIST|ISO|EU|OWASP)-[A-Za-z0-9.\-]+)"', text))

    def test_every_ref_in_risk_engine_is_a_known_control(self):
        refs = self._refs_in_source()
        assert any(r.startswith("OWASP-") for r in refs)
        assert refs <= _all_ids(), sorted(refs - _all_ids())

    def test_every_rule_ref_resolves(self):
        for rule in RISK_RULES:
            assert set(rule.get("framework_refs", [])) <= _all_ids(), rule["title"]

    def test_reachability_matches_the_documented_gap_list(self):
        used = self._refs_in_source()
        owasp = {c for c in _all_ids() if c.startswith("OWASP-")}
        assert owasp - used == UNREACHABLE


class TestMapper:
    def _status(self, mappings, cid):
        return next(m.status for m in mappings if m.control_id == cid)

    def test_gap_partial_mapped(self):
        risks = [
            {"title": "t", "severity": Severity.HIGH, "framework_refs": ["OWASP-LLM06"]},
            {"title": "u", "severity": Severity.LOW, "framework_refs": ["OWASP-ASI03"],
             "mitigation_status": "mitigated"},
            {"title": "v", "severity": Severity.LOW, "framework_refs": ["OWASP-LLM02"],
             "mitigation_status": "mitigated", "evidence_qualifier": "repository_wide"},
        ]
        mappings = map_controls(risks)
        assert self._status(mappings, "OWASP-LLM06") == CoverageStatus.PARTIAL
        assert self._status(mappings, "OWASP-ASI03") == CoverageStatus.MAPPED
        assert self._status(mappings, "OWASP-LLM02") == CoverageStatus.PARTIAL
        assert self._status(mappings, "OWASP-LLM04") == CoverageStatus.GAP

    def test_json_lists_all_twenty(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        data = json.loads(format_json(scan_directory(tmp_path)))
        by_fw = {}
        for m in data["control_mappings"]:
            by_fw.setdefault(m["framework"], []).append(m)
        assert len(by_fw[LLM]) == 10 and len(by_fw[ASI]) == 10
        assert {m["status"] for m in by_fw[LLM] + by_fw[ASI]} <= {"mapped", "partial", "gap"}


def _unpinned_repo(tmp_path):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "loose": {"command": "npx", "args": ["-y", "some-mcp"]},
        "tight": {"command": "npx", "args": ["-y", "other-mcp@1.2.3"]},
    }}))
    return tmp_path


class TestUnpinnedMcp:
    def test_fires_with_server_evidence(self, tmp_path):
        result = scan_directory(_unpinned_repo(tmp_path))
        (risk,) = [r for r in result.risks if r["title"] == UNPINNED_MCP_TITLE]
        assert risk["severity"] == "medium" and risk["evidence_basis"] == "observed"
        assert len(risk["evidence"]) == 1 and risk["evidence"][0].startswith("loose some-mcp .mcp.json:")
        assert risk["framework_refs"] == ["NIST-MAP-2.3", "ISO-42001-A.8.2", "OWASP-LLM03", "OWASP-ASI04"]

    def test_silent_when_pinned_or_unknown(self, tmp_path):
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
            "a": {"command": "npx", "args": ["-y", "x@1.0.0"]},
            "b": {"command": "node", "args": ["s.js"]},
            "c": {"url": "https://h.example/mcp"},
            "d": {"command": "npx", "args": ["tsx", "./server.ts"]},
            "e": {"command": "docker", "args": ["run", "-i", "--rm", "my-mcp-server"]},
        }}))
        assert not [r for r in scan_directory(tmp_path).risks if r["title"] == UNPINNED_MCP_TITLE]

    def test_evidence_capped_at_ten(self):
        servers = [{"name": f"s{i}", "command": "npx", "args": ["-y", f"p{i}"], "pinned": False, "file": "m.json",
                    "line": i} for i in range(13)]
        (risk,) = [r for r in classify_risks([], mcp_servers=servers) if r["title"] == UNPINNED_MCP_TITLE]
        assert len(risk["evidence"]) == 11 and risk["evidence"][-1] == "... and 3 more"


class TestCodeExecution:
    def test_fires_with_tool_evidence(self, tmp_path):
        (tmp_path / "agent.py").write_text("from crewai_tools import CodeInterpreterTool\ntools = [CodeInterpreterTool()]\n")
        (risk,) = [r for r in scan_directory(tmp_path).risks if r["title"] == CODE_EXEC_TITLE]
        assert risk["severity"] == "medium" and risk["evidence"] == ["CodeInterpreterTool agent.py:1"]
        assert "OWASP-ASI05" in risk["framework_refs"] and risk["evidence_basis"] == "observed"

    def test_silent_on_import_alone(self, tmp_path):
        (tmp_path / "agent.py").write_text("from crewai_tools import CodeInterpreterTool\n")
        result = scan_directory(tmp_path)
        assert [t["referenced"] for t in result.tool_capabilities] == [False]
        assert not [r for r in result.risks if r["title"] == CODE_EXEC_TITLE]

    def test_fires_on_module_attribute_use(self, tmp_path):
        (tmp_path / "agent.py").write_text("import crewai_tools as ct\ntool = ct.CodeInterpreterTool()\n")
        assert [r for r in scan_directory(tmp_path).risks if r["title"] == CODE_EXEC_TITLE]

    def test_silent_without_code_execution(self, tmp_path):
        (tmp_path / "agent.py").write_text("from crewai_tools import BraveSearchTool\n")
        assert not [r for r in scan_directory(tmp_path).risks if r["title"] == CODE_EXEC_TITLE]

    def test_not_from_providers_alone(self):
        assert not [r for r in classify_risks(["crewai", "mcp"]) if r["title"] in (CODE_EXEC_TITLE, UNPINNED_MCP_TITLE)]


class TestOutputs:
    def test_sarif_carries_owasp_ids_as_tags(self, tmp_path):
        repo = _unpinned_repo(tmp_path)
        (repo / "agent.py").write_text("from crewai_tools import CodeInterpreterTool\nimport mcp\ntools = [CodeInterpreterTool()]\n")
        sarif = json.loads(format_sarif(scan_directory(repo)))
        tags = {t for rule in sarif["runs"][0]["tool"]["driver"]["rules"] for t in rule["properties"]["tags"]}
        assert {"OWASP-LLM03", "OWASP-ASI04", "OWASP-ASI05", "OWASP-LLM06"} <= tags

    def test_new_findings_are_not_consolidated(self):
        caps = [{"tool": "x.Code", "classes": ["code_execution"], "source": "import", "file": "a.py", "line": 1}]
        risks = risk_engine.consolidate_risks(classify_risks(["crewai", "mcp"], tool_capabilities=caps))
        assert CODE_EXEC_TITLE in {r["title"] for r in risks}
        assert TRIFECTA_TITLE not in {r["title"] for r in risks}

    def test_linked_rules_carry_owasp_refs_last(self):
        by_title = {r["title"]: r["framework_refs"] for r in RISK_RULES}
        for title, ids in {
            "API keys potentially exposed in source code": ["OWASP-LLM02", "OWASP-ASI03"],
            "AI orchestration framework adds supply chain risk": ["OWASP-LLM03", "OWASP-ASI04"],
            "MCP server exposes tools without governance controls": ["OWASP-LLM06", "OWASP-ASI02", "OWASP-ASI03"],
            "Agentic AI framework without human oversight controls": ["OWASP-LLM06", "OWASP-ASI09"],
            "AI agent tool use without access controls": ["OWASP-LLM06", "OWASP-ASI02"],
        }.items():
            assert by_title[title][-len(ids):] == ids
