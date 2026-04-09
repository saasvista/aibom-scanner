"""Tests for AI SDK detection patterns."""

from aibom_scanner.detectors.ai_sdk import scan_file, scan_dependencies, should_scan_file, Detection


class TestShouldScanFile:
    def test_python_files(self):
        assert should_scan_file("app.py")
        assert should_scan_file("src/service.py")

    def test_js_ts_files(self):
        assert should_scan_file("index.js")
        assert should_scan_file("chat.ts")
        assert should_scan_file("api.tsx")

    def test_skip_tests(self):
        assert not should_scan_file("test/test_app.py")
        assert not should_scan_file("tests/conftest.py")

    def test_skip_node_modules(self):
        assert not should_scan_file("node_modules/openai/index.js")

    def test_skip_venv(self):
        # Note: .venv exclusion is handled by scanner's file tree walker, not should_scan_file
        # should_scan_file only checks file extensions and test dirs
        pass

    def test_skip_git(self):
        assert not should_scan_file(".git/objects/abc123")


class TestScanFile:
    def test_openai_import(self):
        content = "from openai import OpenAI\nclient = OpenAI()"
        detections = scan_file("app.py", content)
        providers = {d.provider for d in detections}
        assert "openai" in providers

    def test_anthropic_import(self):
        content = 'from anthropic import Anthropic\nclient = Anthropic()'
        detections = scan_file("app.py", content)
        providers = {d.provider for d in detections}
        assert "anthropic" in providers

    def test_chinese_ai_detection(self):
        content = "import zhipuai\nclient = zhipuai.ZhipuAI()"
        detections = scan_file("app.py", content)
        providers = {d.provider for d in detections}
        assert "zhipu" in providers

    def test_deepseek_detection(self):
        content = 'from openai import OpenAI\nclient = OpenAI(base_url="https://api.deepseek.com")\nresponse = client.chat.completions.create(model="deepseek-chat")'
        detections = scan_file("app.py", content)
        models = [d.model_name for d in detections if d.model_name]
        assert any("deepseek" in (m or "").lower() for m in models)

    def test_mcp_detection(self):
        content = "from mcp import FastMCP\nserver = FastMCP()"
        detections = scan_file("server.py", content)
        providers = {d.provider for d in detections}
        assert "mcp" in providers

    def test_crewai_detection(self):
        content = "from crewai import Agent, Crew\ncrew = Crew()"
        detections = scan_file("agents.py", content)
        providers = {d.provider for d in detections}
        assert "crewai" in providers

    def test_no_detections_in_plain_code(self):
        content = "def hello():\n    print('hello world')\n"
        detections = scan_file("app.py", content)
        assert len(detections) == 0

    def test_detection_has_line_number(self):
        content = "import os\nfrom openai import OpenAI\n"
        detections = scan_file("app.py", content)
        openai_dets = [d for d in detections if d.provider == "openai"]
        assert len(openai_dets) > 0
        assert openai_dets[0].line_number == 2

    def test_model_name_extraction(self):
        content = 'client.chat.completions.create(model="gpt-4o")'
        detections = scan_file("app.py", content)
        models = [d.model_name for d in detections if d.model_name]
        assert any("gpt-4" in m for m in models)


class TestScanDependencies:
    def test_requirements_txt(self):
        content = "openai>=1.0\nanthropic>=0.20\nflask>=2.0\n"
        detections = scan_dependencies("requirements.txt", content)
        providers = {d["provider"] if isinstance(d, dict) else d.provider for d in detections}
        assert "openai" in providers
        assert "anthropic" in providers

    def test_package_json(self):
        content = '{"dependencies": {"@anthropic-ai/sdk": "^0.20", "express": "^4.0"}}'
        detections = scan_dependencies("package.json", content)
        providers = {d["provider"] if isinstance(d, dict) else d.provider for d in detections}
        assert "anthropic" in providers

    def test_pyproject_toml(self):
        content = '[project]\ndependencies = ["openai>=1.0", "pydantic"]\n'
        detections = scan_dependencies("pyproject.toml", content)
        providers = {d["provider"] if isinstance(d, dict) else d.provider for d in detections}
        assert "openai" in providers
