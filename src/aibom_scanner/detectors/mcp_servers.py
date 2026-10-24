"""Per-server MCP inventory: which MCP servers a repo configures or starts, never their credentials.

Two sources:
  - config files (mcp.json, .mcp.json, mcp_config.json, claude_desktop_config.json), any language
  - Python code, via one AST visitor driven by the constructor table below

Hard rule: no value ever reaches the output. Only key NAMES are stored for env and headers, URLs are
reduced to scheme + host, and `args` is emitted through an ALLOWLIST: flag names, `--flag=<redacted>`,
the package / image spec of npx, uvx, pipx run and docker run, and docker `-e NAME=<redacted>`.
Every other argument (paths, positionals, flag values) is shown as "<arg>". A command that is not a
plain program name is shown as "<redacted>".

The list of MCP client constructor names was derived from splx-ai/agentic-radar (Apache-2.0).
See NOTICE.
"""

import ast
import json
import re
from urllib.parse import urlsplit

MCP_CONFIG_FILENAMES = {"mcp.json", ".mcp.json", "mcp_config.json", "claude_desktop_config.json"}
MCP_CONFIG_KEYS = ("mcpServers", "servers")
MAX_JSON_BYTES = 1_000_000

MCP_SERVERS_NOTE = (
    "MCP servers are extracted from config files (any repo) and Python code only. "
    "Servers defined in C#, TypeScript or Go source are detected at import level, not listed per server."
)

# fully-qualified constructor -> (transport, framework). "framework" None = decide from file imports.
_CONSTRUCTORS: dict[str, tuple[str, str | None]] = {
    "mcp.StdioServerParameters": ("stdio", None),
    "mcp.client.stdio.StdioServerParameters": ("stdio", None),
    "agents.mcp.MCPServerStdio": ("stdio", "openai_agents"),
    "agents.mcp.server.MCPServerStdio": ("stdio", "openai_agents"),
    "agents.mcp.MCPServerSse": ("sse", "openai_agents"),
    "agents.mcp.server.MCPServerSse": ("sse", "openai_agents"),
    "agents.mcp.MCPServerStreamableHttp": ("http", "openai_agents"),
    "agents.mcp.server.MCPServerStreamableHttp": ("http", "openai_agents"),
    "agents.HostedMCPTool": ("hosted", "openai_agents"),
    "agents.tool.HostedMCPTool": ("hosted", "openai_agents"),
    "autogen_ext.tools.mcp.StdioServerParams": ("stdio", "autogen"),
    "autogen_ext.tools.mcp.SseServerParams": ("sse", "autogen"),
    "autogen_ext.tools.mcp.StreamableHttpServerParams": ("http", "autogen"),
}
_MULTI_CLIENT = "langchain_mcp_adapters.client.MultiServerMCPClient"
_CREWAI_ADAPTERS = {"crewai_tools.MCPServerAdapter", "crewai_tools.tools.mcp_tool.MCPServerAdapter"}
_QUICK_FILTER = ("StdioServer", "SseServer", "StreamableHttp", "MCPServer", "HostedMCPTool", "MultiServerMCPClient")

_TRANSPORT_NAMES = {
    "stdio": "stdio", "sse": "sse", "http": "http", "streamable_http": "http", "streamable-http": "http",
    "streamablehttp": "http", "streamable_http_server": "http", "hosted": "hosted",
}

_ENV_FLAGS = {"-e", "--env"}
_REDACTED = "<redacted>"
_DYNAMIC = "<dynamic>"
_ARG = "<arg>"
_BARE_FLAG = re.compile(r"^-{1,2}[A-Za-z][\w-]*$")
_SPEC = re.compile(r"^[@\w./:=+-]{1,120}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_COMMAND = re.compile(r"^[\w./\\:@+-]{1,200}$")
_VERSION = re.compile(r"^v?\d[\w.+\-]*$")


def is_mcp_config_path(rel_path: str) -> bool:
    return rel_path.replace("\\", "/").split("/")[-1].lower() in MCP_CONFIG_FILENAMES


# --- redaction ---


def url_host(url: object) -> str | None:
    """Reduce a URL to scheme://host[:port]. Drops userinfo, path and query."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https", "ws", "wss") or not host:
        return None
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def _safe_spec(spec: str) -> bool:
    """A package / image spec: charset-limited, and `=` only as `name==<version>`."""
    if not _SPEC.match(spec):
        return False
    if "=" not in spec:
        return True
    name, sep, version = spec.partition("==")
    return bool(name) and bool(sep) and "=" not in name and bool(_VERSION.match(version))


def _cmd_name(command: str | None) -> str:
    cmd = (command or "").replace("\\", "/").split("/")[-1].lower()
    return re.sub(r"\.(cmd|exe)$", "", cmd)


def redact_args(args: list, command: str | None = None) -> list[str]:
    """Allowlist redaction. Every element is emitted as exactly one of:
    a bare flag name; `--flag=<redacted>`; the package / image spec of an npx, uvx, pipx run or docker run
    command; docker `-e NAME=<redacted>`; the literal `run`; or `<arg>`. Values are never emitted.
    """
    cmd = _cmd_name(command)
    spec_idx = _spec_index(cmd, args)
    run_idx = args.index("run") if cmd in ("docker", "pipx") and "run" in args else None
    out: list[str] = []
    for i, a in enumerate(args):
        if not isinstance(a, str) or a == _DYNAMIC:
            out.append(_DYNAMIC)
        elif cmd == "docker" and i > 0 and args[i - 1] in _ENV_FLAGS:
            name = a.split("=", 1)[0]
            out.append(f"{name}={_REDACTED}" if _ENV_NAME.match(name) else _ARG)
        elif i == spec_idx:
            if "://" in a:
                out.append(url_host(a) or _ARG)
            else:
                out.append(a if _safe_spec(a) else _ARG)
        elif i == run_idx:
            out.append(a)
        elif a.startswith("-"):
            if "=" in a:
                flag = a.split("=", 1)[0]
                out.append(f"{flag}={_REDACTED}" if _BARE_FLAG.match(flag) else _ARG)
            else:
                out.append(a if _BARE_FLAG.match(a) else _ARG)
        else:
            out.append(_ARG)
    return out


def _env_names_from_args(command: str | None, args: list) -> list[str]:
    """Names set via docker `-e NAME=value` / `--env NAME`."""
    if _cmd_name(command) != "docker":
        return []
    return [
        a.split("=", 1)[0] for prev, a in zip(args, args[1:])
        if prev in _ENV_FLAGS and isinstance(a, str) and _ENV_NAME.match(a.split("=", 1)[0])
    ]


# --- pinned ---

# Flags that take no value. A positional after any OTHER flag is that flag's value, never the spec.
_BOOL_FLAGS = {
    "npx": {"-y", "--yes", "-q", "--quiet", "--no-install", "--no"},
    "uvx": {"-q", "--quiet", "--isolated", "--no-cache", "--offline"},
    "pipx": {"--no-cache", "--quiet", "-q"},
    "docker": {"--rm", "-i", "-t", "-it", "-d", "--detach", "--init", "--read-only", "--privileged",
               "--interactive", "--tty"},
}
_SPEC_FLAGS = {"npx": {"-p", "--package"}, "uvx": {"--from"}, "pipx": {"--spec"}}
# Flags known to take one value. A flag in neither set means the scanner cannot tell where the package
# is, so there is no spec (fail closed: a secret positional must never be taken for the package).
_VALUE_FLAGS = {
    "npx": {"--registry", "--cache", "--userconfig"},
    "uvx": {"--python", "-p", "--with", "--index-url", "--default-index"},
    "pipx": {"--python", "--index-url"},
    "docker": {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-w", "--workdir", "-u",
               "--user", "--network", "--net", "--entrypoint", "--mount", "-l", "--label", "--env-file",
               "--platform", "--pull", "-m", "--memory", "--cpus", "--add-host", "--hostname"},
}


def _known_flag(cmd: str, a: str) -> bool:
    return "=" in a or a in _BOOL_FLAGS[cmd] or a in _VALUE_FLAGS[cmd] or a in _SPEC_FLAGS.get(cmd, ())


def _first_positional(args: list, cmd: str, start: int = 0) -> int | None:
    """First argument that is a positional and not the value of a flag. None when an unknown flag comes first."""
    bool_flags, value_flags = _BOOL_FLAGS[cmd], _VALUE_FLAGS[cmd] | _SPEC_FLAGS.get(cmd, set())
    i = start
    while i < len(args):
        a = args[i]
        if isinstance(a, str) and a.startswith("-"):
            if not _known_flag(cmd, a):
                return None
            i += 2 if "=" not in a and a in value_flags else 1
            continue
        return None if a == _DYNAMIC or not isinstance(a, str) else i
    return None


def _flag_value(args: list, names: set[str]) -> int | None:
    for i, a in enumerate(args[:-1]):
        if a in names:
            return None if args[i + 1] == _DYNAMIC else i + 1
    return None


def _spec_index(cmd: str, args: list) -> int | None:
    """Index of the package / image argument for npx, uvx, pipx run and docker run, else None.

    The single source of truth for both compute_pinned and redact_args."""
    if cmd not in _BOOL_FLAGS:
        return None
    start = 0
    if cmd == "pipx":
        if not args or args[0] != "run":
            return None
        start = 1
    elif cmd == "docker":
        if "run" not in args:
            return None
        start = args.index("run") + 1
    explicit = _flag_value(args, _SPEC_FLAGS[cmd]) if cmd in _SPEC_FLAGS else None
    if explicit is None:
        return _first_positional(args, cmd, start)
    unknown = any(isinstance(a, str) and a.startswith("-") and not _known_flag(cmd, a) for a in args[start:explicit])
    return None if unknown else explicit


def server_package(server: dict) -> str | None:
    """Package or image name (version and tag stripped) of an inventoried npx, uvx, pipx run or docker run server."""
    args = server.get("args") or []
    cmd = _cmd_name(server.get("command"))
    idx = _spec_index(cmd, args)
    if idx is None or "://" in args[idx] or not _safe_spec(args[idx]):
        return None
    spec = args[idx]
    if cmd == "docker":
        spec = spec.split("@", 1)[0]
        head, sep, tag = spec.rpartition(":")
        return head if sep and "/" not in tag else spec
    if cmd == "npx":
        return _npx_name(spec)
    return spec.split("==", 1)[0].split("@", 1)[0]


def _npx_name(spec: str) -> str:
    """npx package name with the version stripped (`@scope/pkg@1.2` -> `@scope/pkg`)."""
    name, _, _ = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
    return ("@" if spec.startswith("@") else "") + name


def _versioned(spec: str, seps: tuple[str, ...]) -> bool:
    """True when spec is name<sep>version with a concrete version (not latest, not a range)."""
    for sep in seps:
        idx = spec.rfind(sep)
        if idx > 0 and _VERSION.match(spec[idx + len(sep):]):
            return True
    return False


# npx packages that run a script from the repo (`npx tsx ./server.ts`): the server code is local, not a package.
_NPX_SCRIPT_RUNNERS = {"tsx", "ts-node", "node"}
_LOCAL_REGISTRIES = ("localhost/", "localhost:", "127.0.0.1/", "127.0.0.1:")


def _local_docker_image(spec: str) -> bool:
    """An image built locally: no registry or namespace (`my-server`), or a localhost registry.

    Docker Hub official images also have no namespace, but MCP server images are published under one
    (`mcp/github`, `ghcr.io/...`)."""
    return "/" not in spec.split("@", 1)[0] or spec.startswith(_LOCAL_REGISTRIES)


def compute_pinned(command: str | None, args: list) -> bool | None:
    """True/False for npx, uvx, pipx run and docker run; None for everything else. Runs on the original args.

    None also for a local script run through npx (`npx tsx ./server.ts`) and a locally built docker image:
    there is no published version to pin."""
    if not command or any(not isinstance(a, str) for a in args):
        return None
    cmd = _cmd_name(command)
    idx = _spec_index(cmd, args)
    if idx is None:
        return None
    spec = args[idx]
    if cmd == "npx":
        if _npx_name(spec) in _NPX_SCRIPT_RUNNERS:
            return None
        return _versioned(spec, ("@",))
    if cmd == "uvx":
        return _versioned(spec, ("==", "@"))
    if cmd == "pipx":
        return _versioned(spec, ("==",))
    if "@sha256:" in spec:
        return True
    if _local_docker_image(spec):
        return None
    tag = spec.rsplit(":", 1)[1] if ":" in spec.rsplit("/", 1)[-1] else ""
    return bool(tag) and tag != "latest"


# --- record building ---


def _record(
    *, name, transport, command, args, url, env_keys, header_keys, source, framework, file, line,
) -> dict:
    args = [a if isinstance(a, str) else _DYNAMIC for a in (args or [])]
    command = command if isinstance(command, str) else None
    safe_command = (
        command is not None and bool(_COMMAND.match(command)) and "://" not in command and "@" not in command
    )
    arg_env = _env_names_from_args(command if safe_command else None, args)
    env = sorted({k for k in (env_keys or []) if isinstance(k, str)} | set(arg_env))
    return {
        "name": name if isinstance(name, str) else None,
        "transport": transport,
        "command": command if safe_command or command is None else _REDACTED,
        "args": redact_args(args, command if safe_command else None),
        "url_host": url_host(url),
        "env_keys": env,
        "header_keys": sorted({k for k in (header_keys or []) if isinstance(k, str)}),
        "source": source,
        "framework": framework,
        "file": file,
        "line": line,
        "pinned": compute_pinned(command, args) if safe_command else None,
    }


def _transport_from_config(cfg: dict) -> str:
    declared = cfg.get("type", cfg.get("transport"))
    if isinstance(declared, str) and declared.lower() in _TRANSPORT_NAMES:
        return _TRANSPORT_NAMES[declared.lower()]
    if cfg.get("command"):
        return "stdio"
    url = cfg.get("url", cfg.get("serverUrl"))
    if isinstance(url, str):
        try:
            if urlsplit(url).path.rstrip("/").endswith("/sse"):
                return "sse"
        except ValueError:
            pass
    return "unknown"


# --- config files ---


def scan_mcp_json(rel_path: str, content: str) -> list[dict]:
    """Named MCP config files read `mcpServers` and `servers`. Any other .json file up to 1 MB
    whose text contains "mcpServers" is read for the `mcpServers` key only."""
    if is_mcp_config_path(rel_path):
        return scan_mcp_config(rel_path, content)
    if rel_path.lower().endswith(".json") and len(content) <= MAX_JSON_BYTES and '"mcpServers"' in content:
        return scan_mcp_config(rel_path, content, keys=("mcpServers",))
    return []


_JSON_STRING = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"(\s*:)?')


def _key_line_map(content: str) -> dict[str, int]:
    """Map each JSON object key to the 1-based line of its first occurrence, in one linear pass."""
    lines: dict[str, int] = {}
    line = 1
    last = 0
    for m in _JSON_STRING.finditer(content):
        if not m.group(2):
            continue
        line += content.count("\n", last, m.start())
        last = m.start()
        name = m.group(1)
        if "\\" in name:
            try:
                name = json.loads('"' + name + '"')
            except ValueError:
                continue
        lines.setdefault(name, line)
    return lines


def scan_mcp_config(rel_path: str, content: str, keys: tuple[str, ...] = MCP_CONFIG_KEYS) -> list[dict]:
    """Extract servers from an MCP client config file. Malformed JSON returns []."""
    try:
        data = json.loads(content)
    except RecursionError:
        raise
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    servers = []
    key_lines: dict[str, int] | None = None
    for key in keys:
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, cfg in block.items():
            if not isinstance(cfg, dict):
                continue
            args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            env, headers = cfg.get("env"), cfg.get("headers")
            if key_lines is None:
                key_lines = _key_line_map(content)
            line = key_lines.get(name, 0)
            servers.append(_record(
                name=name,
                transport=_transport_from_config(cfg),
                command=cfg.get("command"),
                args=args,
                url=cfg.get("url", cfg.get("serverUrl")),
                env_keys=list(env) if isinstance(env, dict) else [],
                header_keys=list(headers) if isinstance(headers, dict) else [],
                source="config",
                framework="mcp_config",
                file=rel_path,
                line=line,
            ))
    return servers


# --- Python code ---


class _McpVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.servers: list[dict] = []
        self.imports: dict[str, str] = {}  # local name -> fully qualified
        self.star_modules: list[str] = []
        self.targets: dict[int, str] = {}  # id(Call) -> variable it is assigned to
        self.dict_vars: dict[str, ast.Dict] = {}
        self.client_vars: set[str] = set()
        self.uses_crewai = False

    # imports
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imports[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            self.uses_crewai |= a.name.split(".")[0] == "crewai"

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return
        self.uses_crewai |= node.module.split(".")[0] == "crewai"
        for a in node.names:
            if a.name == "*":
                self.star_modules.append(node.module)
            else:
                self.imports[a.asname or a.name] = f"{node.module}.{a.name}"

    def _fq(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.imports:
                return self.imports[node.id]
            for mod in self.star_modules:
                cand = f"{mod}.{node.id}"
                if cand in _CONSTRUCTORS or cand == _MULTI_CLIENT or cand in _CREWAI_ADAPTERS:
                    return cand
            return None
        if isinstance(node, ast.Attribute):
            base = self._fq(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    # targets
    def _note_target(self, value: ast.AST, target: ast.AST | None) -> None:
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(target, ast.Name):
            if isinstance(value, ast.Call):
                self.targets[id(value)] = target.id
            elif isinstance(value, ast.Dict):
                self.dict_vars[target.id] = value

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1:
            self._note_target(node.value, node.targets[0])
            self._note_client(node.value, node.targets[0])
        self.generic_visit(node)

    def _visit_with(self, node) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._note_target(item.context_expr, item.optional_vars)
                self._note_client(item.context_expr, item.optional_vars)
        self.generic_visit(node)

    visit_With = visit_AsyncWith = _visit_with

    def _note_client(self, value: ast.AST, target: ast.AST) -> None:
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call) and isinstance(target, ast.Name) and self._fq(value.func) == _MULTI_CLIENT:
            self.client_vars.add(target.id)

    # calls
    def visit_Call(self, node: ast.Call) -> None:
        fq = self._fq(node.func)
        if fq in _CONSTRUCTORS:
            self._constructor(node, *_CONSTRUCTORS[fq])
        elif fq == _MULTI_CLIENT:
            self._multi_client(node)
        elif fq in _CREWAI_ADAPTERS:
            self._crewai_adapter(node)
        elif (
            isinstance(node.func, ast.Attribute) and node.func.attr == "connect_to_server"
            and isinstance(node.func.value, ast.Name) and node.func.value.id in self.client_vars
        ):
            name = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
            self._add_from_fields(_fields(node), name, None, node.lineno, "langgraph")
        self.generic_visit(node)

    def _constructor(self, node: ast.Call, transport: str, framework: str | None) -> None:
        fields = _fields(node)
        for wrapper in ("params", "tool_config"):
            if wrapper in fields:
                inner = fields[wrapper]
                if isinstance(inner, ast.Name):
                    inner = self.dict_vars.get(inner.id)
                fields.update(_fields(inner))
        if "server_url" in fields:
            fields.setdefault("url", fields["server_url"])
        name = _const(fields.get("name")) or _const(fields.get("server_label")) or self.targets.get(id(node))
        fw = framework or ("crewai" if self.uses_crewai else "mcp")
        self._add_from_fields(fields, name, transport, node.lineno, fw)

    def _multi_client(self, node: ast.Call) -> None:
        conns = node.args[0] if node.args else _fields(node).get("connections")
        if isinstance(conns, ast.Name):
            conns = self.dict_vars.get(conns.id)
        if not isinstance(conns, ast.Dict):
            return
        for k, v in zip(conns.keys, conns.values):
            fields = _fields(v)
            if fields:
                self._add_from_fields(fields, _const(k), None, getattr(v, "lineno", node.lineno), "langgraph")

    def _crewai_adapter(self, node: ast.Call) -> None:
        arg = node.args[0] if node.args else _fields(node).get("serverparams")
        if isinstance(arg, ast.Name):
            arg = self.dict_vars.get(arg.id)
        if isinstance(arg, ast.Dict):
            self._add_from_fields(_fields(arg), self.targets.get(id(node)), None, node.lineno, "crewai")

    def _add_from_fields(self, fields: dict, name, transport: str | None, line: int, framework: str) -> None:
        args_node = fields.get("args")
        args = [_const(e) if _const(e) is not None else _DYNAMIC for e in args_node.elts] \
            if isinstance(args_node, (ast.List, ast.Tuple)) else []
        declared = _const(fields.get("transport")) or _const(fields.get("type"))
        if transport is None:
            transport = _TRANSPORT_NAMES.get(declared.lower(), "unknown") if declared else (
                "stdio" if "command" in fields else "unknown")
        self.servers.append(_record(
            name=name, transport=transport, command=_const(fields.get("command")), args=args,
            url=_const(fields.get("url")), env_keys=_dict_keys(fields.get("env")),
            header_keys=_dict_keys(fields.get("headers")), source="code", framework=framework,
            file=self.rel_path, line=line,
        ))


def _const(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _dict_keys(node: ast.AST | None) -> list[str]:
    if not isinstance(node, ast.Dict):
        return []
    return [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]


def _fields(node: ast.AST | None) -> dict[str, ast.AST]:
    """Keyword arguments of a call, or the string keys of a dict literal, as name -> value node."""
    if isinstance(node, ast.Call):
        return {kw.arg: kw.value for kw in node.keywords if kw.arg}
    if isinstance(node, ast.Dict):
        return {k.value: v for k, v in zip(node.keys, node.values)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return {}


def scan_mcp_python(rel_path: str, content: str) -> list[dict]:
    """Extract servers from Python source. A file with a syntax error yields [].

    A RecursionError (from ast.parse or the visitor) is re-raised. When the visitor raised it, the servers
    collected before the error are attached as `err.partial` (a list); a parse-time error has no `partial`."""
    if not any(token in content for token in _QUICK_FILTER):
        return []
    try:
        tree = ast.parse(content)
    except RecursionError:
        raise
    except (SyntaxError, ValueError, MemoryError):
        return []
    visitor = _McpVisitor(rel_path)
    try:
        visitor.visit(tree)
    except RecursionError as err:
        err.partial = visitor.servers
        raise
    return visitor.servers


def scan_mcp_file(rel_path: str, content: str) -> list[dict]:
    """Dispatch on file type: MCP config files and .py files."""
    if is_mcp_config_path(rel_path):
        return scan_mcp_config(rel_path, content)
    if rel_path.endswith(".py"):
        return scan_mcp_python(rel_path, content)
    return []
