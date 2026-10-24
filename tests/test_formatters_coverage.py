"""Tests for coverage and evidence_basis on the JSON, SARIF, and table surfaces."""

import json

import pytest

from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import INFERRED_PREAMBLE, format_table
from aibom_scanner.scanner import scan_directory


@pytest.fixture
def mixed_repo(tmp_path):
    """A repo with a real detection plus an unreadable language."""
    (tmp_path / "app.py").write_text("import openai\nclient = OpenAI()\n")
    (tmp_path / "deploy.ps1").write_text("Write-Host hi\n")
    return tmp_path


@pytest.fixture
def no_ai_repo(tmp_path):
    """A repo with no AI usage — every finding is inferred."""
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    return tmp_path


class TestJsonFormatter:
    def test_coverage_serializes(self, mixed_repo):
        data = json.loads(format_json(scan_directory(mixed_repo)))
        assert data["coverage"]["source_files_seen"] == 2
        assert data["coverage"]["unsupported_languages"] == [".ps1"]
        assert data["coverage"]["unscanned_by_extension"] == {".ps1": 1}

    def test_both_ratios_serialize(self, mixed_repo):
        cov = json.loads(format_json(scan_directory(mixed_repo)))["coverage"]
        assert cov["coverage_pct"] == 50.0
        assert cov["readable_coverage_pct"] == 50.0

    def test_evidence_basis_serializes(self, mixed_repo):
        data = json.loads(format_json(scan_directory(mixed_repo)))
        assert all("evidence_basis" in r for r in data["risks"])

    def test_empty_repo_coverage_serializes(self, empty_repo):
        data = json.loads(format_json(scan_directory(empty_repo)))
        assert data["coverage"]["source_files_seen"] == 0


class TestSarifFormatter:
    def test_inferred_findings_produce_no_results(self, no_ai_repo):
        result = scan_directory(no_ai_repo)
        assert all(r["evidence_basis"] == "inferred" for r in result.risks)
        sarif = json.loads(format_sarif(result))
        assert sarif["runs"][0]["results"] == []

    def test_observed_findings_produce_results(self, mixed_repo):
        sarif = json.loads(format_sarif(scan_directory(mixed_repo)))
        assert sarif["runs"][0]["results"]

    def test_result_count_equals_observed_count(self, mixed_repo):
        result = scan_directory(mixed_repo)
        observed = [r for r in result.risks if r["evidence_basis"] == "observed"]
        sarif = json.loads(format_sarif(result))
        assert len(sarif["runs"][0]["results"]) == len(observed)

    def test_coverage_in_run_properties(self, mixed_repo):
        sarif = json.loads(format_sarif(scan_directory(mixed_repo)))
        assert sarif["runs"][0]["properties"]["coverage"]["source_files_seen"] == 2

    def test_coverage_in_invocation(self, mixed_repo):
        sarif = json.loads(format_sarif(scan_directory(mixed_repo)))
        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["properties"]["coverage"]["unsupported_languages"] == [".ps1"]
        assert invocation["executionSuccessful"] is True

    def test_incomplete_coverage_emits_notification(self, mixed_repo):
        sarif = json.loads(format_sarif(scan_directory(mixed_repo)))
        notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert len(notifications) == 1
        assert ".ps1" in notifications[0]["message"]["text"]

    def test_unread_source_file_emits_notification(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        (tmp_path / "big.py").write_text("x = 1\n" * 200_000)
        sarif = json.loads(format_sarif(scan_directory(tmp_path)))
        notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        assert len(notifications) == 1
        assert "1 .py files were not read" in notifications[0]["message"]["text"]

    def test_complete_coverage_emits_no_notification(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        sarif = json.loads(format_sarif(scan_directory(tmp_path)))
        assert "toolExecutionNotifications" not in sarif["runs"][0]["invocations"][0]

    def test_rules_exclude_inferred_findings(self, no_ai_repo):
        sarif = json.loads(format_sarif(scan_directory(no_ai_repo)))
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


class TestTableFormatter:
    def test_coverage_line_carries_denominator(self, mixed_repo):
        out = format_table(scan_directory(mixed_repo))
        assert "of" in out and "source files (50.0%)" in out

    def test_observed_section_rendered(self, mixed_repo):
        out = format_table(scan_directory(mixed_repo))
        assert "Observed in code" in out

    def test_inferred_section_rendered_with_preamble(self, no_ai_repo):
        out = format_table(scan_directory(no_ai_repo))
        assert "Governance checklist — not observed in code" in out
        assert INFERRED_PREAMBLE in out

    def test_no_inferred_section_when_all_observed(self, tmp_repo):
        result = scan_directory(tmp_repo)
        assert all(r["evidence_basis"] == "observed" for r in result.risks)
        assert "Governance checklist" not in format_table(result)

    def test_unreadable_language_warning(self, mixed_repo):
        out = format_table(scan_directory(mixed_repo))
        assert "INCOMPLETE COVERAGE" in out
        assert "1 .ps1 files" in out

    def test_no_warning_when_coverage_complete(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\n")
        assert "INCOMPLETE COVERAGE" not in format_table(scan_directory(tmp_path))

    def test_missing_coverage_falls_back_to_plain_count(self, mixed_repo):
        result = scan_directory(mixed_repo)
        result.coverage = None
        assert "Scanned" in format_table(result)
