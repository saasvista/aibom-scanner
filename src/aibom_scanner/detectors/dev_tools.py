"""Detect AI development tools (Cursor, Copilot, etc.) in repository config."""
import re
from dataclasses import dataclass


@dataclass
class DevToolDetection:
    tool_name: str
    file_path: str
    confidence: float
    evidence: str


DEV_TOOL_INDICATORS = [
    ("cursor", ".cursorrules", 1.0),
    ("cursor", ".cursor/", 1.0),
    ("github_copilot", ".github/copilot-instructions.md", 1.0),
    ("github_copilot", ".copilot", 0.9),
    ("codeium", ".codeium", 0.9),
    ("tabnine", ".tabnine", 0.9),
    ("aider", ".aider.conf.yml", 1.0),
    ("continue", ".continue/", 0.9),
    ("claude_code", "CLAUDE.md", 1.0),
]


def detect_dev_tools(file_paths: list[str]) -> list[DevToolDetection]:
    """Detect AI dev tools from a list of repository file paths."""
    detections = []
    for tool_name, indicator, confidence in DEV_TOOL_INDICATORS:
        for fp in file_paths:
            if indicator in fp:
                detections.append(DevToolDetection(
                    tool_name=tool_name,
                    file_path=fp,
                    confidence=confidence,
                    evidence=f"Found {indicator} in repository",
                ))
                break
    return detections
