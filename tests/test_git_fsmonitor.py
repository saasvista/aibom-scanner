"""G1: scanning must not run a program named in the scanned repository's git config."""

import os
import shutil
import subprocess

import pytest

from aibom_scanner.scanner import scan_directory

GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(GIT is None, reason="git not installed")


def _env(tmp_path):
    return dict(
        os.environ, HOME=str(tmp_path / "home"), GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
    )


def test_repo_fsmonitor_command_is_not_run(tmp_path, monkeypatch):
    (tmp_path / "home").mkdir()
    for k, v in _env(tmp_path).items():
        monkeypatch.setenv(k, v)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "app.py").write_text("import openai\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, check=True)
    marker = tmp_path / "marker.txt"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\necho ran > {marker}\n")
    hook.chmod(0o755)
    # The repository's own config names a program for git to run on every status
    # or file listing. The scan must not run it.
    subprocess.run(["git", "config", "core.fsmonitor", str(hook)], cwd=repo, check=True)
    result = scan_directory(repo)
    assert not marker.exists()
    assert result.summary["total_detections"] >= 1
