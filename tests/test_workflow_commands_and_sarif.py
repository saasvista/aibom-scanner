"""Workflow-command neutralization in json/table/sarif, and SARIF locations and stable rule ids."""

import json
import subprocess

import pytest

from aibom_scanner.formatters.json_fmt import format_json
from aibom_scanner.formatters.sarif_fmt import format_sarif
from aibom_scanner.formatters.table_fmt import format_table
from aibom_scanner.scanner import scan_directory

GIT = ["git", "-c", "user.email=t@example.com", "-c", "user.name=t"]


def _repo(path, files):
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    for name, text in files.items():
        (path / name).write_text(text)
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run([*GIT, "commit", "-q", "-m", "init"], cwd=path, check=True)
    return path


@pytest.fixture
def hostile(tmp_path):
    mcp = {"mcpServers": {
        "##[add-mask]probe": {"command": "npx", "args": ["some-server"]},
        "##[stop-commands]tok1": {"command": "npx", "args": ["other-server"]},
    }}
    repo = _repo(tmp_path / "hostile", {
        "##[warning]probe.py": "import openai\n",
        ".mcp.json": json.dumps(mcp),
    })
    return scan_directory(repo)


class TestWorkflowCommands:
    def test_no_command_marker_in_any_output(self, hostile):
        for out in (format_json(hostile), format_table(hostile), format_sarif(hostile)):
            assert "##[" not in out

    def test_json_round_trips_original_names(self, hostile):
        data = json.loads(format_json(hostile))
        assert any(d["file_path"] == "##[warning]probe.py" for d in data["detections"])
        assert any(s["name"] == "##[add-mask]probe" for s in data["mcp_servers"])

    def test_sarif_round_trips_original_path(self, hostile):
        sarif = json.loads(format_sarif(hostile))
        uris = {
            loc["physicalLocation"]["artifactLocation"]["uri"]
            for r in sarif["runs"][0]["results"] for loc in r["locations"]
        }
        assert "##[warning]probe.py" in uris

    def test_triple_hash_is_neutralized(self, tmp_path):
        repo = _repo(tmp_path / "r", {"###[x]y.py": "import openai\n"})
        result = scan_directory(repo)
        for out in (format_json(result), format_table(result), format_sarif(result)):
            assert "##[" not in out
        assert json.loads(format_json(result))["detections"][0]["file_path"] == "###[x]y.py"


def _sarif(tmp_path, name, files):
    return json.loads(format_sarif(scan_directory(_repo(tmp_path / name, files))))["runs"][0]


def _by_title(run, fragment):
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    return [rid for rid, r in rules.items() if fragment in r["shortDescription"]["text"]]


class TestSarif:
    def test_every_result_has_a_location(self, tmp_path):
        run = _sarif(tmp_path, "a", {"app.py": "import openai\n", "ds.py": "import deepseek\n"})
        assert run["results"]
        for res in run["results"]:
            assert res["locations"]
            phys = res["locations"][0]["physicalLocation"]
            assert phys["artifactLocation"]["uri"]
            assert phys["region"]["startLine"] >= 1

    def test_location_prefers_affected_provider_file(self, tmp_path):
        run = _sarif(tmp_path, "a", {"app.py": "import openai\n", "ds.py": "x = 1\nimport deepseek\n"})
        sov = _by_title(run, "overeign")
        ds = [r for r in run["results"] if r["ruleId"] in sov]
        assert ds
        phys = ds[0]["locations"][0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "ds.py"
        assert phys["region"]["startLine"] == 2

    def test_rule_ids_stable_when_a_provider_is_added(self, tmp_path):
        base = _sarif(tmp_path, "base", {"app.py": "import openai\n", "ds.py": "import deepseek\n"})
        more = _sarif(tmp_path, "more", {
            "app.py": "import openai\n", "ds.py": "import deepseek\n", "zp.py": "import zhipuai\n",
        })
        base_ids = {r["id"] for r in base["tool"]["driver"]["rules"]}
        more_ids = {r["id"] for r in more["tool"]["driver"]["rules"]}
        assert base_ids <= more_ids
        assert more_ids - base_ids, "adding zhipuai should add a rule"
        assert _by_title(base, "Entity List") == []
        assert _by_title(more, "Entity List")
        assert not set(_by_title(more, "Entity List")) & base_ids
        sov = _by_title(base, "overeign")
        assert sov and sov == _by_title(more, "overeign")

    def test_rule_ids_ascii_and_unique(self, tmp_path):
        run = _sarif(tmp_path, "a", {"app.py": "import openai\n", "ds.py": "import deepseek\n"})
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(ids) == len(set(ids))
        titles = {r["shortDescription"]["text"] for r in run["tool"]["driver"]["rules"]}
        assert len(titles) == len(ids)
        for rid in ids:
            assert rid.isascii() and rid.startswith("aibom/")
            assert not rid.rsplit("/", 1)[1].isdigit()
        for res in run["results"]:
            assert res["ruleId"] in ids
