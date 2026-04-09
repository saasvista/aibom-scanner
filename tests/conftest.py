"""Test fixtures for aibom-scanner."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure src is on path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def tmp_repo(tmp_path):
    """Create a temporary directory with sample AI code."""
    # Python file with OpenAI usage
    py_file = tmp_path / "app.py"
    py_file.write_text("""
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": user_input}],
)
""")

    # Requirements file
    req = tmp_path / "requirements.txt"
    req.write_text("openai>=1.0\nanthropic>=0.20\nlangchain>=0.1\n")

    # JS file with Anthropic
    js_dir = tmp_path / "src"
    js_dir.mkdir()
    js_file = js_dir / "chat.js"
    js_file.write_text("""
const { Anthropic } = require("@anthropic-ai/sdk");
const client = new Anthropic();
const response = await client.messages.create({
    model: "claude-3-5-sonnet-20241022",
    messages: [{ role: "user", content: req.body.message }],
});
""")

    # .env file (secrets management signal)
    env_file = tmp_path / ".env.example"
    env_file.write_text("OPENAI_API_KEY=sk-xxxx\n")

    # .gitignore
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text(".env\nnode_modules/\n")

    return tmp_path


@pytest.fixture
def chinese_ai_repo(tmp_path):
    """Create a repo with Chinese AI provider usage."""
    py_file = tmp_path / "service.py"
    py_file.write_text("""
import zhipuai
from dashscope import Generation

# Zhipu AI (BIS Entity Listed)
client = zhipuai.ZhipuAI(api_key="xxx")

# Alibaba Qwen via DashScope
response = Generation.call(model="qwen-turbo", prompt="hello")
""")
    return tmp_path


@pytest.fixture
def empty_repo(tmp_path):
    """Create an empty directory."""
    return tmp_path


@pytest.fixture
def agentic_repo(tmp_path):
    """Create a repo with agentic AI framework usage."""
    py_file = tmp_path / "agents.py"
    py_file.write_text("""
from crewai import Agent, Task, Crew

agent = Agent(role="researcher", goal="find data")
task = Task(description="research topic", agent=agent)
crew = Crew(agents=[agent], tasks=[task])
result = crew.kickoff()
""")
    return tmp_path
