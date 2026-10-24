"""G5: a scan root below the working directory must not pass through a symlink."""

import json
import os

import pytest

from aibom_scanner.cli import main
from aibom_scanner.scanner import scan_directory


@pytest.fixture
def tree(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("import openai  # OUTSIDE_MARKER\n")
    (work / "realdir").mkdir()
    (work / "realdir" / "a.py").write_text("import openai\n")
    os.symlink(str(outside), work / "svc")
    os.symlink("../outside", work / "rel")
    monkeypatch.chdir(work)
    return work


def test_symlinked_subdir_exits_2(tree, capsys):
    with pytest.raises(SystemExit) as e:
        main(["scan", "--path", "svc", "--format", "json"])
    assert e.value.code == 2
    assert "OUTSIDE_MARKER" not in capsys.readouterr().out


def test_symlinked_parent_component_exits_2(tree):
    with pytest.raises(SystemExit) as e:
        main(["scan", "--path", "rel/../outside", "--format", "json"])
    assert e.value.code == 2
    with pytest.raises(ValueError):
        scan_directory("svc/sub")


@pytest.mark.parametrize("given", [".", "realdir", "svc/../realdir"])
def test_normal_paths_still_work(tree, given):
    assert scan_directory(given).metadata["path"]


def test_absolute_path_outside_cwd_still_works(tree, tmp_path):
    result = scan_directory(str(tmp_path / "outside"))
    assert result.summary["total_detections"] >= 1
