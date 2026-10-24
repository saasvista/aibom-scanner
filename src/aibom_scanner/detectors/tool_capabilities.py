"""Capability classes for the tools an agent can call.

Classes: untrusted_content_in, sensitive_data_access, external_side_effect, code_execution, model_call.
Python tools are matched by import (aliases resolved per file), SDK modules by import root, and MCP servers
by their package spec, taken from the WO-A1 inventory. A server whose package is not in the table gets no classes. Never guessed from a name.

The python_tools data was copied from splx-ai/agentic-radar (Apache-2.0) and re-keyed. See NOTICE.
"""

import ast
import json
from functools import lru_cache
from pathlib import Path

from aibom_scanner.detectors.mcp_servers import server_package

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "tool_capabilities.json"
CAPABILITY_CLASSES = (
    "untrusted_content_in", "sensitive_data_access", "external_side_effect", "code_execution", "model_call",
)
# Import roots that re-export catalog classes from shorter paths (langchain_community.tools.X vs .tools.x.y.X)
_REEXPORT_ROOTS = ("langchain", "crewai_tools")


@lru_cache(maxsize=1)
def load_data() -> dict:
    with open(DATA_FILE, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _by_class_name() -> dict[str, tuple[str, ...]]:
    """Class name -> classes, only when every catalog path with that name agrees."""
    seen: dict[str, set[tuple[str, ...]]] = {}
    for path, classes in load_data()["python_tools"].items():
        name = path.rsplit(".", 1)[-1]
        if name[:1].isupper():
            seen.setdefault(name, set()).add(tuple(classes))
    return {n: next(iter(v)) for n, v in seen.items() if len(v) == 1}


def _classes_for(fq: str) -> list[str] | None:
    exact = load_data()["python_tools"].get(fq)
    if exact is not None:
        return exact
    if fq.split(".")[0].startswith(_REEXPORT_ROOTS):
        return list(_by_class_name().get(fq.rsplit(".", 1)[-1], ())) or None
    return None


def scan_tool_imports(rel_path: str, content: str) -> list[dict]:
    """Classified tools imported or referenced in a Python file. Syntax errors yield [].

    A RecursionError (from ast.parse) is re-raised, so the caller can record the file as not fully analysed."""
    modules = load_data()["python_modules"]
    if not rel_path.endswith(".py") or not any(root in content for root in (*_REEXPORT_ROOTS, *modules)):
        return []
    try:
        tree = ast.parse(content)
    except RecursionError:
        raise
    except (SyntaxError, ValueError, MemoryError):
        return []
    imports: dict[str, str] = {}
    found: dict = {}

    def record(fq: str, line: int) -> None:
        classes = _classes_for(fq)
        if classes and fq not in found:
            found[fq] = {"tool": fq, "classes": list(classes), "source": "import", "file": rel_path, "line": line,
                         "referenced": False}

    def resolve(node: ast.AST) -> str | None:
        attrs = []
        while isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id not in imports:
            return None
        return ".".join([imports[node.id], *reversed(attrs)])

    def record_module(name: str, line: int) -> None:
        root = name.split(".")[0]
        if root in modules and ("module", root) not in found:
            found[("module", root)] = {
                "tool": root, "classes": list(modules[root]), "source": "import", "file": rel_path, "line": line,
                "referenced": False,
            }

    def mark_referenced(fq: str) -> None:
        for key in (fq, ("module", fq.split(".")[0])):
            if key in found:
                found[key]["referenced"] = True

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                record_module(a.name, node.lineno)
                imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                record(a.name, node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            record_module(node.module, node.lineno)
            for a in node.names:
                imports[a.asname or a.name] = f"{node.module}.{a.name}"
                record(f"{node.module}.{a.name}", node.lineno)
    # A use is any name or attribute outside an import statement that resolves to an imported tool.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)):
            fq = resolve(node)
            if fq:
                if isinstance(node, ast.Attribute):
                    record(fq, node.lineno)
                mark_referenced(fq)
    return list(found.values())


def mcp_capabilities(mcp_servers: list[dict]) -> list[dict]:
    """Classes for inventoried MCP servers whose package (version stripped) is in the table."""
    table = load_data()["mcp_packages"]
    out = []
    for s in mcp_servers:
        pkg = server_package(s)
        if pkg and pkg in table:
            out.append({"tool": pkg, "classes": list(table[pkg]), "source": "mcp_server",
                        "file": s.get("file"), "line": s.get("line")})
    return out


def capability_classes(tool_capabilities: list[dict]) -> list[str]:
    return sorted({c for t in tool_capabilities for c in t["classes"]})
