# Changelog

## Unreleased

### Fixed

- **TOML manifests are parsed instead of scanned for package name substrings.** `pyproject.toml` and
  `Pipfile` were read by looking for each known package name as a substring of every line, so
  `dependencies = ["langchain-openai>=0.1.0"]` was reported as three dependencies — `langchain-openai`,
  `langchain` and `openai` — and a provider the project never declared reached the report and the risk
  rules. A package name is now matched whole. The version is read from the requirement instead of the
  line, so a TOML dependency reports its pinned version like the equivalent `requirements.txt` or
  `package.json` entry; it was always `null` before. PEP 508 requirement strings, Poetry and Pipfile
  version constraints, inline tables, extras and environment markers are handled.

## 1.3.0 (2026-10-13)

Per-server MCP inventory.

### Added

- **`mcp_servers` in the scan result.** Each MCP server the repo configures or starts is listed with
  name, transport (`stdio`, `sse`, `http`, `hosted`, `unknown`), command, args, URL host, env and header
  key names, source (`config` or `code`), framework, file, line, and `pinned` (true/false for `npx`, `uvx`,
  `pipx run` and `docker run`, null otherwise). Sources: `mcp.json`, `.mcp.json`, `mcp_config.json` and
  `claude_desktop_config.json` (top-level `mcpServers` or `servers`), and Python code through one
  table-driven AST visitor covering `mcp.StdioServerParameters`, `MultiServerMCPClient`, the OpenAI Agents
  `MCPServerStdio` / `MCPServerSse` / `MCPServerStreamableHttp` / `HostedMCPTool`, the AutoGen
  `StdioServerParams` / `SseServerParams` / `StreamableHttpServerParams`, and CrewAI adapters.
  Import aliases are resolved per file.
- **No values are stored.** Env and header entries are key names only, URLs are reduced to scheme and host,
  and `args` is an allowlist: flag names, `--flag=<redacted>`, the package or image spec of `npx`, `uvx`,
  `pipx run` and `docker run`, and docker `-e NAME=<redacted>`. Every other argument (paths, positionals,
  flag values) is shown as `<arg>`. A command that is not a plain program name is shown as `<redacted>`.
- **Content-based config detection.** Any `.json` file up to 1 MB that contains `"mcpServers"` is read as an
  MCP config (the `mcpServers` key only).
- **Per-server risk evidence.** "MCP server exposes tools without governance controls" now carries
  `name (transport) file:line` evidence for each server found. With only an MCP import detected, the
  finding is unchanged. A configured server counts as MCP detected, so a repo with only an MCP config file
  also gets the MCP and agentic-governance findings, the unpinned-server finding and the capability
  findings, at MEDIUM at most (qualifier `mcp_config_only` where a finding was lowered), so a build that
  passed on 1.2.0 with the default `high` threshold still passes. It does not get the provider-wide
  findings (exposed keys, model governance and so on): those need a real SDK detection.
- **Coverage note.** `summary.mcp_servers_note` states that servers defined in C#, TypeScript or Go
  source are not extracted per server. The table output gains an "MCP Servers" section.
- **Tool capability classes.** `tool_capabilities` lists tools with a capability class
  (`untrusted_content_in`, `sensitive_data_access`, `external_side_effect`, `code_execution`, `model_call`),
  matched by Python import against `data/tool_capabilities.json` (about 500 LangChain and CrewAI tools, seeded from
  agentic-radar's catalogs plus a small hand-classified set) and by MCP package name. `summary.capability_classes`
  lists the classes present. The table output gains a "Tool Capabilities" section.
- **New finding (HIGH or MEDIUM):** "Codebase combines untrusted input, sensitive data access and an action
  capability". It fires only from named tools (untrusted content in AND sensitive data access AND external side
  effect or code execution), never from provider detection alone, with a scope line and one evidence line per
  class. It is HIGH when a single file holds the legs in at least two distinct tools and at least one of them was
  found in code (a Python import; same module). Servers listed only in an MCP config file give MEDIUM with
  qualifier `mcp_config`: a config file shows availability to one client, not use. It is MEDIUM with qualifier
  `repository_wide` when the legs are spread across files. Eleven web search, scrape and browser
  SDK modules (`tavily`, `firecrawl`,
  `playwright` and others) are classed `untrusted_content_in` by import.
- **OWASP mappings.** Two control tables, "OWASP LLM Top 10 (2025)" (`OWASP-LLM01`..`10`) and "OWASP Agentic Top 10
  (2026)" (`OWASP-ASI01`..`10`), join the NIST, ISO and EU tables in `control_mappings`. Existing findings link to
  them: exposed API keys, orchestration supply chain, MCP governance, human oversight, tool access, and the
  combined-capability finding. Nine items have no static signal and read GAP: LLM04, LLM07, LLM08, LLM09, LLM10,
  ASI06, ASI07, ASI08 and ASI10.
- **Two findings:** "MCP server launched without a pinned version" (MEDIUM, one evidence line per unpinned server)
  and "Agent tool can execute code" (MEDIUM, one evidence line per tool). Both are built from inventory data, never
  from provider detection.
- `NOTICE` file: the MCP constructor list and the tool-to-category data were derived from splx-ai/agentic-radar
  (Apache-2.0).

### Fixed

- **`code_snippet` masks key-shaped strings and credential assignments.** A detection's source line is masked
  before it is stored. Masked: `sk-` tokens of 20 or more characters (including `sk-proj-` and keys with `_`),
  the other known key shapes, and quoted values (single, double or backtick quotes, optional `f` / `r` / `b`
  prefix) assigned to credential-looking names (`api_key="..."`, `token: "..."`). They become `<redacted>`.
  Env lookups such as `os.environ["X"]` are untouched. Not masked: a value passed positionally to a
  constructor, a value inside a URL (`user:pass@host`) or a header dict value, which can still appear in a snippet.
- **Hardcoded keys are no longer written to the JSON output.** `secrets[].raw_value` held the full key.
  Behavior change: `secrets[].raw_value` is no longer part of the JSON output; `redacted_value` remains.
- **`redacted_value` shows less of the key.** It was the first 8 and last 4 characters, which is more than half of
  the shortest key formats. It is now the first 4 and last 2.

## 1.2.0 (2026-07-21)

.NET detection depth.

1.1.0 taught the scanner to open `.cs`/`.fs`/`.vb` files; it still could not
understand them. 28 of the existing patterns are import-shaped (`from x`,
`import x`, `require('x')`) and none matched a C# `using` directive, and no NuGet
manifest format was parsed. Measured on `OneIdentity/safeguard-mcp`: 1 detection
across 13,689 lines of C#, and zero dependencies, despite the repo declaring
`ModelContextProtocol 1.4.0` in its `.csproj` and using it in 12 source files.

### Added

- **C# `using`-directive patterns.** 9 new patterns covering `ModelContextProtocol`
  (including the `[McpServerTool]` / `[McpServerResource]` attribute family),
  `Microsoft.SemanticKernel`, `Azure.AI.OpenAI`, `OpenAI`, `Anthropic`,
  `Amazon.BedrockRuntime`, `Google.Cloud.AIPlatform`, and `Mscc.GenerativeAI`.
  Every pattern is anchored to line start and requires a PascalCase namespace, so
  `using`-as-resource-disposal (`using var client = ...`, `using (var stream = ...)`)
  never triggers a false positive.
- **NuGet manifest parsing.** `.csproj`, `.fsproj`, `.vbproj`, `Directory.Packages.props`,
  and `packages.config` are now parsed for `PackageReference` / `PackageVersion` /
  `package` elements, matched against a new NuGet-specific package map
  (`NUGET_DEPENDENCY_MAP`) using longest dot-boundary prefix matching, so
  `Azure.AI.OpenAI` resolves to `azure_openai` and never collides with `openai`.
  Central package management's optional `Version` attribute is handled — a
  missing version does not drop the dependency. Manifests are parsed with regex,
  not an XML parser, and a malformed manifest degrades to no dependencies found
  rather than raising.
- These manifests are scannable but are not counted as source, exactly like
  `package.json` today — `coverage_pct` is unaffected by their presence.

### Result on the measured fixture

`OneIdentity/safeguard-mcp`: 1 detection / 0 dependencies before this release,
23 detections / 2 dependencies after, with `mcp` correctly surfaced as a detected
provider and `ModelContextProtocol` surfaced as a dependency.

## 1.1.0 (2026-07-21)

An accuracy release, correcting error in both directions.

An AI Bill of Materials that silently omits what it could not parse is not incomplete,
it is wrong. 1.0.0 under-reported by never opening whole languages, and over-reported
by inferring providers from local module names and from the AWS SDK. This release makes
every unread file visible, labels every evidence-free finding as such, and stops
attributing providers a repository does not use.

### Behavior change — `--severity-threshold`

**`--severity-threshold` now counts observed findings only.** In 1.0.0 the gate
counted every finding, including the 18 governance rules that fire on empty input,
so any repository tripped `--severity-threshold high` regardless of what was in it.
The flag was unusable: without it every scan exited 0 (false green), with it every
scan exited 1 (false red on fabricated findings).

If your CI relied on 1.0.0 always failing, it will now pass unless the scan actually
observed AI usage at or above the threshold. This is the intended fix.

This also repairs the **GitHub Action**, which passes `--severity-threshold` on every
run (default `high`). Under 1.0.0 three governance rules fired on every repository, so
the Action failed every build regardless of what the code contained. It is usable now.
The Action gains a `fail-on-incomplete-coverage` input.

### Added

- **Coverage accounting.** Every scan reports how much of the repo's source it read,
  with a denominator. Two ratios, because either alone misleads:
  `coverage_pct` (scanned / all source seen) and `readable_coverage_pct`
  (scanned / source we intended to read, i.e. excluding tests and fixtures).
- **`--fail-on-incomplete-coverage`** — opt-in, exits `3` when the scanner could not
  read some source languages. Off by default so existing CI does not break on upgrade.
- **Coverage warning on stderr** whenever languages were unreadable, in every output
  format. Written to stderr so it cannot corrupt piped JSON or SARIF.
- **`evidence_basis` on every finding** — `observed` (backed by something in the
  scanned source) or `inferred` (no evidence, no detected providers).
- Table output splits findings into "Observed in code" and
  "Governance checklist — not observed in code".
- SARIF carries coverage in `runs[0].properties` and `runs[0].invocations[0]`, plus a
  `toolExecutionNotification` when coverage is incomplete.
- New scannable extensions: `.cs`, `.fs`, `.vb`, `.vue`, `.svelte`, `.cjs`, `.sh`,
  `.swift`. A 243-file C# repository previously scanned 27 files and read zero `.cs`.

### Changed

- **SARIF emits only observed findings as results.** A governance checklist item is
  not a defect at a code location, and 1.0.0 pushed them into GitHub Code Scanning as
  authoritative alerts.
- Comment-led lines and asset imports (`import Logo from "anthropic.svg"`) no longer
  produce detections. Real usage — `import openai  # noqa`, `require("openai")`,
  `base_url="https://api.deepseek.com"` — is unaffected.

### Fixed — false-positive providers ([#2](https://github.com/saasvista/aibom-scanner/issues/2))

The same release that stops the scanner under-reporting also stops it over-reporting.

- **`replicate`, `together` and `cohere` import patterns are anchored to line start.**
  These provider names are common English words, so `from app.services import replicate`
  — a local module — was reported as Replicate.com usage. Any repository with a
  same-named module was mis-flagged. Top-level, indented, submodule and JavaScript
  `require()` imports are all still detected.
- **`boto3` no longer maps to `aws_bedrock`.** `boto3` is the entire AWS SDK, so its
  presence flagged Bedrock for any repository touching S3, SQS or DynamoDB. Bedrock is
  now detected from actual usage (`bedrock-runtime`, `bedrock.invoke_model`,
  `BedrockRuntime`), which was already specific and correct.

Thanks to [@nandanadileep](https://github.com/nandanadileep) ([#3](https://github.com/saasvista/aibom-scanner/pull/3)),
whose line-anchoring approach for `cohere` was the right shape and is incorporated here,
extended to the other two affected providers and the dependency mapping.

### Not in this release

Detection depth for the newly-readable languages (C# `using` directives, NuGet
manifest parsing) is a 1.2 concern. 1.1.0 reads `.cs` files and honestly reports
finding little, which is correct and a large improvement over not reading them.

## 1.0.0 (2026-04-10)

Initial release.

- 61 AI SDK detection patterns across 30+ providers
- 10 Chinese AI providers with BIS Entity List flagging (3 CRITICAL)
- Agentic AI framework detection (CrewAI, AutoGen, LangGraph, Semantic Kernel, MCP)
- 34 risk rules across 8 categories with evidence qualification
- 48 compliance controls mapped to NIST AI RMF, ISO 42001, EU AI Act
- Secrets management detection (Vault, AWS SM, dotenv, hardcoded keys)
- Dev tool detection (Cursor, Copilot, Claude Code, Aider, etc.)
- Output formats: table (terminal), JSON, SARIF (GitHub Code Scanning)
- GitHub Action for CI integration
- Zero dependencies beyond Python stdlib
