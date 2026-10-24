"""Run-2 audit: inputs dropped or failed without a coverage signal (G2, G3, G4, G6, D2, S3)."""

import json
import os
import shutil
import subprocess

import pytest

import aibom_scanner.scanner as scanner_mod
from aibom_scanner.cli import main
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.scanner import scan_directory

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not installed")
CODE = "from openai import OpenAI\nclient = OpenAI()\n"
PAD = " " * 1_100_000


@pytest.fixture
def git_env(tmp_path, monkeypatch):
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for k in ("NAME", "EMAIL"):
        monkeypatch.setenv(f"GIT_AUTHOR_{k}", "t")
        monkeypatch.setenv(f"GIT_COMMITTER_{k}", "t")


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def _write(root, rel, text=CODE):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _run(argv, capsys):
    with pytest.raises(SystemExit) as e:
        main(argv)
    cap = capsys.readouterr()
    return e.value.code, cap


def _no_exit(argv, capsys):
    try:
        main(argv)
        code = 0
    except SystemExit as e:
        code = e.code or 0
    return code, capsys.readouterr()


# --- G2 ---

def test_oversize_mcp_config_trips_gate(tmp_path, capsys):
    cfg = {"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(cfg) + PAD)
    code, cap = _no_exit(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"], capsys)
    assert code == 3
    assert "warning: incomplete coverage: 1 inputs were not fully analysed (too_large: 1)" in cap.err
    assert json.loads(cap.out)["coverage"]["incomplete_inputs"] == {"too_large": 1}


def test_oversize_package_json_trips_gate(tmp_path, capsys):
    (tmp_path / "package.json").write_text('{"dependencies": {"openai": "^4.0.0"}}' + PAD)
    code, cap = _no_exit(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"], capsys)
    assert code == 3
    assert json.loads(cap.out)["coverage"]["incomplete_inputs"] == {"too_large": 1}


def test_oversize_unrelated_json_does_not_trip_gate(tmp_path, capsys):
    (tmp_path / "data.json").write_text("{}" + PAD)
    (tmp_path / "app.py").write_text(CODE)
    code, _ = _no_exit(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"], capsys)
    assert code == 0


def test_unreadable_config_counts_as_parse_error(tmp_path, monkeypatch):
    (tmp_path / ".mcp.json").write_text("{}")
    real = scanner_mod.Path.read_text

    def boom(self, *a, **k):
        if self.name == ".mcp.json":
            raise PermissionError("denied")
        return real(self, *a, **k)

    monkeypatch.setattr(scanner_mod.Path, "read_text", boom)
    assert scan_directory(tmp_path).coverage.incomplete_inputs == {"parse_error": 1}


def test_gate_surfaces_in_table_and_sarif(tmp_path):
    (tmp_path / "package.json").write_text("{}" + PAD)
    result = scan_directory(tmp_path)
    assert result.coverage.is_incomplete()
    assert "INCOMPLETE COVERAGE" in format_table(result)
    notes = json.loads(format_sarif(result))["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any("not fully analysed (too_large: 1)" in n["message"]["text"] for n in notes)


# --- G3 ---

def test_symlinked_source_file_trips_gate(tmp_path, capsys):
    (tmp_path / "real.txt").write_text(CODE)
    os.symlink("real.txt", tmp_path / "agent.py")
    code, cap = _no_exit(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"], capsys)
    assert code == 3
    assert json.loads(cap.out)["coverage"]["incomplete_inputs"] == {"symlink": 1}


def test_symlink_without_source_extension_is_ignored(tmp_path):
    (tmp_path / "real.txt").write_text("x")
    os.symlink("real.txt", tmp_path / "notes.txt")
    assert scan_directory(tmp_path).coverage.incomplete_inputs == {}


@needs_git
def test_gitlink_trips_gate(tmp_path, git_env, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, "app.py", "x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "x")
    sha = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "sub").mkdir()
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sha},sub")
    code, cap = _no_exit(["scan", "--path", str(repo), "--format", "json", "--fail-on-incomplete-coverage"], capsys)
    assert code == 3
    assert json.loads(cap.out)["coverage"]["incomplete_inputs"] == {"submodule": 1}


# --- G4 ---

@needs_git
def test_subdirectory_scan_matches_root_scan(tmp_path, git_env):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, "svc/venv/agent.py")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "x")

    def shape(r):
        return sorted((d["provider"], d["detection_type"]) for d in r.detections)

    root, sub = scan_directory(repo), scan_directory(repo / "svc")
    assert shape(root) and shape(root) == shape(sub)
    assert root.coverage.listing_mode == sub.coverage.listing_mode == "git"
    assert sub.coverage.skipped_by_path == 0


def test_walk_mode_counts_pruned_directories(tmp_path, capsys):
    _write(tmp_path, "venv/agent.py")
    _write(tmp_path, "node_modules/pkg/index.js", "const x = 1;\n")
    _write(tmp_path, "app.py")
    result = scan_directory(tmp_path)
    cov = result.coverage
    assert cov.listing_mode == "walk"
    assert cov.skipped_by_path == 2
    assert cov.skipped_paths == ["node_modules/pkg/index.js", "venv/agent.py"]
    assert cov.files_scanned == 1
    assert cov.files_scanned + cov.skipped_by_path + sum(cov.unscanned_by_extension.values()) == cov.source_files_seen
    err = capsys.readouterr().err
    assert err.startswith("notice:") and "os.walk" in err and err.count("\n") == 1


def test_skipped_paths_capped_at_100(tmp_path):
    for i in range(130):
        _write(tmp_path, f"tests/t{i:03d}.py", "x = 1\n")
    cov = scan_directory(tmp_path).coverage
    assert cov.skipped_by_path == 130
    assert len(cov.skipped_paths) == 100
    assert cov.skipped_paths == sorted(cov.skipped_paths)


# --- G6 ---

def test_detector_exceptions_do_not_abort_scan(tmp_path, monkeypatch, capsys):
    _write(tmp_path, "a.py")
    _write(tmp_path, "b.py")
    _write(tmp_path, "c.py")
    real_scan, real_tools = scanner_mod.scan_file, scanner_mod.scan_tool_imports

    def bad_scan(rel, content):
        if rel == "a.py":
            raise ValueError("boom")
        return real_scan(rel, content)

    def deep_tools(rel, content):
        if rel == "b.py":
            raise RecursionError("deep")
        return real_tools(rel, content)

    monkeypatch.setattr(scanner_mod, "scan_file", bad_scan)
    monkeypatch.setattr(scanner_mod, "scan_tool_imports", deep_tools)
    code, cap = _no_exit(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"], capsys)
    data = json.loads(cap.out)
    assert code == 3
    assert data["coverage"]["incomplete_inputs"] == {"analysis_incomplete": 1, "parse_error": 1}
    files = {d["file_path"] for d in data["detections"]}
    assert files == {"b.py", "c.py"}
    assert "analysis_incomplete: 1, parse_error: 1" in cap.err


def test_partial_results_attached_to_recursion_error_are_kept(tmp_path, monkeypatch):
    _write(tmp_path, "a.py")

    def deep_mcp(rel, content):
        err = RecursionError("deep")
        err.partial = [{"name": "kept", "file": rel, "transport": "stdio"}]
        raise err

    monkeypatch.setattr(scanner_mod, "scan_mcp_file", deep_mcp)
    result = scan_directory(tmp_path)
    assert [s["name"] for s in result.mcp_servers] == ["kept"]
    assert result.coverage.incomplete_inputs == {"analysis_incomplete": 1}


# --- D2 (scanner side) and S3 ---

def _key():
    return "sk-" + "proj-" + "Ab3" * 10 + "_" + "Cd4" * 8


def test_hardcoded_key_in_skipped_path_is_reported_and_tagged(tmp_path):
    _write(tmp_path, "tests/llm.py", f'client = OpenAI(api_key="{_key()}")\n')
    _write(tmp_path, "app.py", "x = 1\n")
    result = scan_directory(tmp_path)
    keys = [s for s in result.secrets if s["evidence_type"] == "hardcoded_key"]
    assert len(keys) == 1
    assert keys[0]["skipped_path"] is True
    assert _key() not in json.dumps(result.secrets)
    assert result.coverage.skipped_by_path == 1 and result.coverage.files_scanned == 1


def test_hardcoded_key_in_normal_path_has_no_skipped_tag(tmp_path):
    _write(tmp_path, "app.py", f'client = OpenAI(api_key="{_key()}")\n')
    keys = [s for s in scan_directory(tmp_path).secrets if s["evidence_type"] == "hardcoded_key"]
    assert keys and "skipped_path" not in keys[0]


def test_oversize_skipped_path_file_is_not_read(tmp_path):
    _write(tmp_path, "tests/big.py", f'k = "{_key()}"\n' + "#" * 1_100_000)
    assert not [s for s in scan_directory(tmp_path).secrets if s["evidence_type"] == "hardcoded_key"]


def test_secrets_management_gets_only_non_skipped_paths(tmp_path, monkeypatch):
    _write(tmp_path, "app.py")
    _write(tmp_path, "tests/.env.example", "X=1\n")
    _write(tmp_path, "tests/helper.py", "x = 1\n")
    seen = {}
    real = scanner_mod.detect_secrets_management

    def spy(file_paths, file_contents, gitignore_content):
        seen["paths"] = list(file_paths)
        return real(file_paths=file_paths, file_contents=file_contents, gitignore_content=gitignore_content)

    monkeypatch.setattr(scanner_mod, "detect_secrets_management", spy)
    scan_directory(tmp_path)
    assert "app.py" in seen["paths"]
    assert not any(p.startswith("tests/") for p in seen["paths"])
