"""F6: scannable files that were rejected or not read must surface in coverage."""

import json
import shutil

from aibom_scanner.cli import main
from aibom_scanner.detectors.ai_sdk import should_scan_file
from aibom_scanner.scanner import scan_directory

CODE = "from openai import OpenAI\nclient = OpenAI()\n"


def _make(tmp_path, rel, text=CODE):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_should_scan_file_is_case_insensitive_and_segment_anchored():
    assert should_scan_file("agent.PY")
    assert should_scan_file("src/metadata/apps/agent.py")
    assert should_scan_file("mydata/raw/agent.py")
    assert not should_scan_file("data/apps/x.py")
    assert not should_scan_file("src/data/raw/x.py")
    assert not should_scan_file("public/data/x.py")
    assert not should_scan_file("Data\\Apps\\x.py")


def test_formerly_rejected_files_are_scanned(tmp_path):
    for rel in ("agent.PY", "src/metadata/apps/agent.py", "mydata/raw/agent.py"):
        _make(tmp_path, rel)
    result = scan_directory(tmp_path)
    assert {d["file_path"] for d in result.detections} == {
        "agent.PY", "src/metadata/apps/agent.py", "mydata/raw/agent.py"}
    assert result.coverage.unread_source_files == {}


def test_data_dir_skip_stays_intentional(tmp_path, capsys):
    _make(tmp_path, "data/apps/x.py")
    result = scan_directory(tmp_path)
    cov = result.coverage
    assert cov.skipped_by_path == 1
    assert cov.unread_source_files == {}
    assert cov.unscanned_by_extension == {}
    main(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"])
    assert "warning" not in capsys.readouterr().err


def test_oversize_file_reported_warned_and_exits_3(tmp_path, capsys):
    _make(tmp_path, "big.py", "import openai\n" + "#" * 1_000_100)
    result = scan_directory(tmp_path)
    cov = result.coverage
    assert cov.unread_source_files == {".py": 1}
    assert cov.unscanned_by_extension == {".py": 1}
    assert cov.files_scanned + cov.skipped_by_path + sum(cov.unscanned_by_extension.values()) == cov.source_files_seen

    try:
        main(["scan", "--path", str(tmp_path), "--format", "json", "--fail-on-incomplete-coverage"])
        code = 0
    except SystemExit as e:
        code = e.code
    captured = capsys.readouterr()
    assert code == 3
    assert "1 .py files were not read" in captured.err
    assert "unsupported" not in captured.err
    assert json.loads(captured.out)["coverage"]["unread_source_files"] == {".py": 1}


def test_table_banner_for_unread(tmp_path, capsys):
    _make(tmp_path, "big.py", "import openai\n" + "#" * 1_000_100)
    main(["scan", "--path", str(tmp_path), "--format", "table"])
    assert "INCOMPLETE COVERAGE" in capsys.readouterr().out
