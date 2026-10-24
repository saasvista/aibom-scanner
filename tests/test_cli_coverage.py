"""Tests for the v1.1.0 CLI behavior: threshold scoping, coverage exit, stderr hygiene."""

import json

import pytest

from aibom_scanner.cli import main


@pytest.fixture
def no_ai_repo(tmp_path):
    """A repo with no AI usage — every finding is inferred."""
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    return tmp_path


@pytest.fixture
def unreadable_repo(tmp_path):
    """A repo the scanner cannot fully read."""
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "deploy.ps1").write_text("Write-Host hi\n")
    return tmp_path


class TestSeverityThreshold:
    def test_threshold_ignores_inferred_findings(self, no_ai_repo, capsys):
        main(["scan", "--path", str(no_ai_repo), "--format", "json", "--severity-threshold", "high"])
        assert capsys.readouterr().out

    def test_threshold_still_trips_on_observed_findings(self, tmp_repo):
        with pytest.raises(SystemExit) as exc:
            main(["scan", "--path", str(tmp_repo), "--format", "json", "--severity-threshold", "medium"])
        assert exc.value.code == 1

    def test_no_threshold_flag_exits_cleanly(self, no_ai_repo, capsys):
        main(["scan", "--path", str(no_ai_repo), "--format", "json"])
        assert capsys.readouterr().out


class TestFailOnIncompleteCoverage:
    def test_exits_3_when_languages_unreadable(self, unreadable_repo):
        with pytest.raises(SystemExit) as exc:
            main([
                "scan", "--path", str(unreadable_repo), "--format", "json",
                "--fail-on-incomplete-coverage",
            ])
        assert exc.value.code == 3

    def test_no_exit_when_coverage_complete(self, tmp_path, capsys):
        (tmp_path / "app.py").write_text("import openai\n")
        main(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"])
        assert capsys.readouterr().out

    def test_opt_in_default_off(self, unreadable_repo, capsys):
        main(["scan", "--path", str(unreadable_repo), "--format", "json"])
        assert capsys.readouterr().out

    def test_severity_exit_takes_precedence(self, tmp_path):
        (tmp_path / "app.py").write_text("import openai\nclient = OpenAI()\n")
        (tmp_path / "deploy.ps1").write_text("Write-Host hi\n")
        with pytest.raises(SystemExit) as exc:
            main([
                "scan", "--path", str(tmp_path), "--format", "json",
                "--severity-threshold", "medium", "--fail-on-incomplete-coverage",
            ])
        assert exc.value.code == 1


class TestStderrHygiene:
    def test_warning_goes_to_stderr(self, unreadable_repo, capsys):
        main(["scan", "--path", str(unreadable_repo), "--format", "json"])
        captured = capsys.readouterr()
        assert "incomplete coverage" in captured.err
        assert "incomplete coverage" not in captured.out

    def test_stdout_stays_valid_json(self, unreadable_repo, capsys):
        main(["scan", "--path", str(unreadable_repo), "--format", "json"])
        data = json.loads(capsys.readouterr().out)
        assert data["coverage"]["unsupported_languages"] == [".ps1"]

    def test_stdout_stays_valid_sarif(self, unreadable_repo, capsys):
        main(["scan", "--path", str(unreadable_repo), "--format", "sarif"])
        data = json.loads(capsys.readouterr().out)
        assert data["version"] == "2.1.0"

    def test_no_warning_when_coverage_complete(self, tmp_path, capsys):
        (tmp_path / "app.py").write_text("import openai\n")
        main(["scan", "--path", str(tmp_path), "--format", "json"])
        assert "warning:" not in capsys.readouterr().err


class TestExitCodePrecedence:
    """When more than one gate trips the result must be deterministic."""

    @pytest.fixture
    def observed_and_unreadable(self, tmp_path):
        """Real AI usage (observed HIGH) AND a language we cannot read."""
        (tmp_path / "app.py").write_text("import openai\nclient = OpenAI()\n")
        (tmp_path / "deploy.ps1").write_text("Write-Host hi\n")
        return tmp_path

    def test_severity_wins_over_coverage(self, observed_and_unreadable):
        """An observed finding is more actionable than a coverage gap, so 1 beats 3."""
        with pytest.raises(SystemExit) as exc:
            main([
                "scan", "--path", str(observed_and_unreadable), "--format", "json",
                "--severity-threshold", "high", "--fail-on-incomplete-coverage",
            ])
        assert exc.value.code == 1

    def test_coverage_gate_alone_returns_3(self, unreadable_repo):
        with pytest.raises(SystemExit) as exc:
            main([
                "scan", "--path", str(unreadable_repo), "--format", "json",
                "--severity-threshold", "high", "--fail-on-incomplete-coverage",
            ])
        assert exc.value.code == 3
