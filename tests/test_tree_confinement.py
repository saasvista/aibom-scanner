"""F3: the scanner reads only regular files inside the scan root."""

import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
from dataclasses import asdict

import pytest

from aibom_scanner.scanner import scan_directory

MARKER = "OUTSIDE_MARKER_77"
GIT = shutil.which("git")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
MCP_JSON = '{"mcpServers": {"%s": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}' % MARKER


def _dump(result):
    return json.dumps(
        {"d": result.detections, "m": result.mcp_servers, "s": result.secrets,
         "t": result.tool_capabilities, "dep": result.dependencies},
        default=str,
    )


def _outside(tmp_path):
    out = tmp_path / "outside"
    out.mkdir()
    (out / "x.py").write_text(f"import openai  # {MARKER}\n")
    (out / "outside.json").write_text(MCP_JSON)
    return out


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    return repo


def _plant_links(tmp_path, repo):
    out = _outside(tmp_path)
    os.symlink("../outside/x.py", repo / "leak.py")
    os.symlink(str(out / "outside.json"), repo / "settings.json")


def test_dev_zero_symlink_is_not_read(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    os.symlink("/dev/zero", repo / "zero.json")
    os.symlink("/dev/zero", repo / "zero.py")
    attempted = []
    real = pathlib.Path.read_text

    def guarded(self, *a, **k):
        if self.name.startswith("zero"):
            attempted.append(self.name)
            return ""  # never touch the device
        return real(self, *a, **k)

    monkeypatch.setattr(pathlib.Path, "read_text", guarded)
    scan_directory(repo)
    assert attempted == []


def test_symlinks_not_followed_non_git(tmp_path):
    repo = _repo(tmp_path)
    _plant_links(tmp_path, repo)
    result = scan_directory(repo)
    assert MARKER not in _dump(result)
    assert result.detections == []
    assert result.coverage.source_files_seen == 1  # app.py only


@pytest.mark.skipif(GIT is None, reason="git not on PATH")
def test_symlinks_not_followed_git(tmp_path):
    repo = _repo(tmp_path)
    _plant_links(tmp_path, repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, env=ENV, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, env=ENV, check=True)
    ls = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True, text=True).stdout
    assert "leak.py" in ls  # the link is tracked, so the filter is what stops it
    result = scan_directory(repo)
    assert MARKER not in _dump(result)
    assert result.detections == []


@pytest.mark.skipif(GIT is None, reason="git not on PATH")
def test_index_entry_with_dotdot_is_dropped(tmp_path):
    out = _outside(tmp_path)
    repo = _repo(tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=repo, env=ENV, check=True)

    def entry(name, sha):
        n = name.encode()
        e = struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 0) + bytes.fromhex(sha)
        e += struct.pack(">H", len(n)) + n
        return e + b"\0" * (8 - (len(e) % 8))

    sha = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    names = sorted(["../outside/x.py", "app.py"])
    body = b"DIRC" + struct.pack(">II", 2, len(names)) + b"".join(entry(n, sha) for n in names)
    (repo / ".git" / "index").write_bytes(body + hashlib.sha1(body).digest())
    ls = subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True, text=True).stdout
    assert "../outside/x.py" in ls
    assert (out / "x.py").exists()
    result = scan_directory(repo)
    assert MARKER not in _dump(result)
    assert result.detections == []
    assert result.coverage.files_in_tree == 1


@pytest.mark.skipif(GIT is None, reason="git not on PATH")
def test_gitdir_file_pointing_elsewhere_reads_nothing_outside(tmp_path):
    out = _outside(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=other, env=ENV, check=True)
    (other / "x.py").write_text(f"import openai  # {MARKER}\n")
    subprocess.run(["git", "add", "x.py"], cwd=other, env=ENV, check=True)
    repo = tmp_path / "repo2"
    repo.mkdir()
    (repo / ".git").write_text(f"gitdir: {other / '.git'}\n")
    assert out.exists()
    result = scan_directory(repo)
    assert MARKER not in _dump(result)
    assert result.detections == []


def test_symlinked_directory_is_not_followed(tmp_path):
    out = _outside(tmp_path)
    repo = _repo(tmp_path)
    os.symlink(str(out), repo / "linkdir")
    result = scan_directory(repo)
    assert MARKER not in _dump(result)


def test_gitignore_symlink_not_read(tmp_path):
    repo = _repo(tmp_path)
    out = tmp_path / "outside"
    out.mkdir()
    (out / "gi").write_text(".env\n")
    os.symlink(str(out / "gi"), repo / ".gitignore")
    # must not raise and must not use the outside file; no assertion on content
    scan_directory(repo)


def test_oversize_source_not_read(tmp_path):
    repo = _repo(tmp_path)
    (repo / "big.py").write_text("import openai\n" + "#" * 1_000_100)
    result = scan_directory(repo)
    assert result.detections == []
    assert result.summary["files_scanned"] == 1
    assert result.coverage.unscanned_by_extension == {".py": 1}
