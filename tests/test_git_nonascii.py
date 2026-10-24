"""F5: git mode lists non-ASCII and control-character file names exactly."""

import os
import shutil
import subprocess

import pytest

from aibom_scanner.scanner import scan_directory

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")

ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
CODE = "from openai import OpenAI\nclient = OpenAI()\n"


def _git_repo(tmp_path, names):
    for n in names:
        (tmp_path / n).write_text(CODE)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, env=ENV, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, env=ENV, check=True)


def test_non_ascii_name_is_scanned(tmp_path):
    _git_repo(tmp_path, ["agént.py"])
    result = scan_directory(tmp_path)
    assert result.detections
    assert {d["file_path"] for d in result.detections} == {"agént.py"}
    assert result.coverage.files_scanned == 1
    assert result.coverage.source_files_seen == 1


def test_tab_in_name_is_listed_exactly(tmp_path):
    _git_repo(tmp_path, ["ag\tent.py", "plain.py"])
    result = scan_directory(tmp_path)
    assert {d["file_path"] for d in result.detections} == {"ag\tent.py", "plain.py"}
    assert result.coverage.source_files_seen == 2
    assert result.coverage.files_scanned == 2
