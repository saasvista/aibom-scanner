"""Tests for CLI argument parsing and output."""

import json
import sys

from aibom_scanner.cli import main


class TestCLI:
    def test_scan_table_output(self, tmp_repo, capsys):
        main(["scan", "--path", str(tmp_repo), "--format", "table"])
        captured = capsys.readouterr()
        assert "AIBOM Scanner Results" in captured.out
        assert "openai" in captured.out.lower()

    def test_scan_json_output(self, tmp_repo, capsys):
        main(["scan", "--path", str(tmp_repo), "--format", "json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "detections" in data
        assert "risks" in data
        assert "summary" in data

    def test_scan_sarif_output(self, tmp_repo, capsys):
        main(["scan", "--path", str(tmp_repo), "--format", "sarif"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "aibom-scanner"

    def test_severity_threshold_exits(self, tmp_repo):
        import pytest
        with pytest.raises(SystemExit) as exc_info:
            main(["scan", "--path", str(tmp_repo), "--severity-threshold", "medium"])
        assert exc_info.value.code == 1

    def test_no_command_exits(self):
        import pytest
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2

    def test_output_to_file(self, tmp_repo, tmp_path):
        out_file = tmp_path / "output.json"
        main(["scan", "--path", str(tmp_repo), "--format", "json", "--output", str(out_file)])
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "detections" in data
