"""Run-2 audit fixes D1-D6: manifest dispatch, skip-path depth, version masking,
JSON shape handling, and linear-time TOML/XML dependency parsing."""

import json
import time

from aibom_scanner.detectors.ai_sdk import (
    _toml_sections,
    is_skipped_path,
    scan_dependencies,
    should_scan_file,
)
from aibom_scanner.scanner import _is_path_skipped, scan_directory

LLM = "import openai\nclient = openai.OpenAI()\n"


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _fast(fn, limit=2.0):
    t = time.perf_counter()
    out = fn()
    assert time.perf_counter() - t < limit
    return out


class TestD1ManifestDispatch:
    def test_should_scan_manifests(self):
        for name in ("requirements.txt", "go.mod", "Pipfile", "svc/Requirements.TXT", "a/GO.MOD", "PIPFILE"):
            assert should_scan_file(name), name
        assert not should_scan_file("notes.txt")
        assert not should_scan_file("x.mod")

    def test_scan_directory_reports_dependencies(self, tmp_path):
        _write(tmp_path, "requirements.txt", "openai==1.30.0\n")
        _write(tmp_path, "go.mod", "module m\nrequire github.com/sashabaranov/go-openai v1.20.0\n")
        _write(tmp_path, "Pipfile", '[packages]\nanthropic = "*"\n')
        result = scan_directory(tmp_path)
        sources = {d["source_file"] for d in result.dependencies}
        assert {"requirements.txt", "go.mod", "Pipfile"} <= sources


class TestD2SkipDepth:
    def test_first_segment_only_for_ambiguous_names(self):
        for seg in ("build", "dist", "vendor", "third_party", "third-party", "example", "examples", "spec", "specs"):
            assert is_skipped_path(f"{seg}/llm.py"), seg
            assert not is_skipped_path(f"src/app/{seg}/llm.py"), seg
            assert not should_scan_file(f"{seg}/llm.py")
            assert should_scan_file(f"src/app/{seg}/llm.py")
            assert _is_path_skipped(f"{seg}/llm.py")
            assert not _is_path_skipped(f"src/app/{seg}/llm.py")

    def test_test_layout_segments_keep_any_depth(self):
        for seg in ("test", "tests", "fixtures", "mock", "mocks", "__tests__", "node_modules"):
            assert is_skipped_path(f"src/app/{seg}/llm.py"), seg
            assert not should_scan_file(f"src/app/{seg}/llm.py")

    def test_scan_directory(self, tmp_path):
        for rel in ("src/app/mock/llm.py", "src/app/vendor/llm.py", "src/app/spec/llm.py",
                    "src/app/example/llm.py", "vendor/llm.py"):
            _write(tmp_path, rel, LLM)
        result = scan_directory(tmp_path)
        files = {d["file_path"] for d in result.detections}
        assert files == {"src/app/vendor/llm.py", "src/app/spec/llm.py", "src/app/example/llm.py"}
        assert result.coverage.skipped_by_path == 2


class TestD3VersionMasking:
    def _secret(self):
        return "ghp_" + "A1b2C3d4" * 5

    def test_package_json_url_spec_masked(self):
        tok = self._secret()
        spec = f"git+https://user:{tok}@example.com/o/r.git"
        out = scan_dependencies("package.json", json.dumps({"dependencies": {"openai": spec}}))
        assert out and tok not in out[0]["version"]

    def test_package_json_version_capped(self):
        out = scan_dependencies("package.json", json.dumps({"dependencies": {"openai": "1" * 500}}))
        assert len(out[0]["version"]) <= 100

    def test_nuget_version_masked_and_capped(self):
        tok = self._secret()
        xml = f'<Project><PackageReference Include="OpenAI" Version="https://u:{tok}@h/{"x" * 300}" /></Project>'
        out = scan_dependencies("a.csproj", xml)
        assert out and tok not in out[0]["version"] and len(out[0]["version"]) <= 100

    def test_pyproject_version_from_spec_capped(self):
        out = scan_dependencies("pyproject.toml", '[tool.poetry.dependencies]\nopenai = "^1.' + "9" * 500 + '"\n')
        assert out and len(out[0]["version"]) <= 100

    def test_normal_versions_unchanged(self):
        out = scan_dependencies("package.json", json.dumps({"dependencies": {"openai": "^4.20.1"}}))
        assert out[0]["version"] == "4.20.1"


class TestD4JsonShapes:
    def test_odd_shapes_give_nothing(self):
        for text in ("[]", '{"dependencies": []}', '{"dependencies": "x"}', '"s"', "null",
                     "[" * 100000, '{"a":' * 100000):
            assert scan_dependencies("package.json", text) == []

    def test_dev_dependencies_still_read(self):
        out = scan_dependencies("package.json", '{"dependencies": [], "devDependencies": {"openai": "1.0.0"}}')
        assert [d["package"] for d in out] == ["openai"]


class TestD5TomlHeader:
    def test_pathological_header_is_fast(self):
        assert _fast(lambda: _toml_sections("[" + " " * 100000 + "x"), 1.0) == []

    def test_sections_on_normal_file(self):
        text = (
            "[project]\nname = 'x'\n\n  [tool.poetry.dependencies] # c\nopenai = '^1'\n"
            "[[tool.x]]\na = 1\n[ spaced ]\nb = 2\n"
        )
        got = _toml_sections(text)
        assert [g[0] for g in got] == ["project", "tool.poetry.dependencies", "", "spaced"]
        assert got[1][2] == "\nopenai = '^1'\n"
        assert got[0][2] == "\nname = 'x'\n\n"


class TestD6LinearManifests:
    N = 1_000_000

    def test_toml_table_unclosed(self):
        c = "[tool.poetry.dependencies]\n" + "a={\n" * (self.N // 4)
        _fast(lambda: scan_dependencies("pyproject.toml", c))

    def test_inline_table_braces(self):
        c = "[dependency-groups]\n" + "{" * self.N
        _fast(lambda: scan_dependencies("pyproject.toml", c))

    def test_xml_comments_unterminated(self):
        c = "<Project>" + "<!--" * (self.N // 4)
        _fast(lambda: scan_dependencies("a.csproj", c))

    def test_xml_elements_unclosed(self):
        for tag, name in (("PackageReference", "a.csproj"), ("PackageVersion", "Directory.Packages.props"),
                          ("package", "packages.config")):
            c = "<Project>" + f"<{tag}" * (self.N // 17)
            _fast(lambda: scan_dependencies(name, c))

    def test_existing_results_identical(self):
        nested = '[tool.poetry.dependencies]\nopenai = {version = "^1.30", source = {url = "x"}}\n'
        assert [d["package"] for d in scan_dependencies("pyproject.toml", nested)] == ["openai"]
        assert scan_dependencies("pyproject.toml", nested)[0]["version"] == "1.30"
        groups = '[dependency-groups]\ndev = ["langchain>=0.2", {include-group = "x"}]\n'
        assert [d["package"] for d in scan_dependencies("pyproject.toml", groups)] == ["langchain"]
        cs = ('<Project><!-- <PackageReference Include="Hidden" Version="9" /> --><ItemGroup>'
              '<PackageReference Include="OpenAI" Version="2.0.0" />'
              '<PackageReference Include="Anthropic.SDK" Version="1.0"></PackageReference></ItemGroup></Project>')
        got = scan_dependencies("a.csproj", cs)
        assert [(d["package"], d["version"]) for d in got] == [("OpenAI", "2.0.0"), ("Anthropic.SDK", "1.0")]

    def test_comment_followed_by_element(self):
        cs = '<!-- unterminated <PackageReference Include="OpenAI" Version="1" />'
        assert scan_dependencies("a.csproj", cs) == []
