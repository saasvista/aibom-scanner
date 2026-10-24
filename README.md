<p align="center">
  <img src="https://raw.githubusercontent.com/saasvista/aibom-scanner/main/docs/banner.png" alt="aibom-scanner" width="100%">
</p>

<p align="center">
  <strong>See what AI is in a codebase and what it can reach: SDKs, models, MCP servers and agent tools.</strong>
</p>

  <a href="https://pypi.org/project/aibom-scanner/"><img src="https://img.shields.io/pypi/v/aibom-scanner?color=blue&label=PyPI" alt="PyPI"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python"></a>
  <a href="https://github.com/saasvista/aibom-scanner/actions/workflows/ci.yml"><img src="https://github.com/saasvista/aibom-scanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/saasvista/aibom-scanner"><img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="Zero Dependencies"></a>
</p>

---

Two questions get hard to answer once a repo has agents in it: what AI is in here, and what can it touch?

`aibom-scanner` reads a codebase and writes an AI Bill of Materials (AIBOM). It lists every AI SDK and model the code
calls, every MCP server it wires up, and every tool an agent can call. Then it shows where those add up to a risk and
which NIST, ISO, EU AI Act and OWASP items each finding points at.

It is a static scan. It makes no network calls, uses no language model, and has zero dependencies. It stores no
values from MCP configs (key names only) and masks key-shaped strings in the code lines it quotes.

## How It Works

<p align="center">
  <img src="https://raw.githubusercontent.com/saasvista/aibom-scanner/main/docs/pipeline.svg" alt="aibom-scanner pipeline: a scan walks the repo, runs the detectors, the risk engine and the control mapper, then writes a table, JSON or SARIF report" width="720">
</p>

```
Your codebase
     |
     v
File walker (git ls-files, os.walk)
     |
     v
Detectors: AI SDKs and models (70 patterns), MCP servers, agent tools, secrets
     |
     v
Risk engine: 34 rules in 8 categories, plus 3 evidence-built findings
     |
     v
Control mapper: 49 controls in 3 frameworks, 20 OWASP items
     |
     v
Table / JSON / SARIF
```

## Quick Start

```bash
pip install aibom-scanner

aibom-scanner scan --path /path/to/your/repo
```

Here is part of the output for a small support agent: one Python file that gives an agent web search, Gmail and a
shell, plus an `.mcp.json` with three servers. Long lines are cut.

```
Risk Findings (10)
  ...
  [HIGH    ] Agentic AI framework without human oversight controls
  [HIGH    ] Codebase combines untrusted input, sensitive data access and an action capability
  [MEDIUM  ] MCP server launched without a pinned version
  [MEDIUM  ] Agent tool can execute code

MCP Servers (3)
  filesystem           stdio    npx                          pinned   .mcp.json:2
  fetch                stdio    uvx                          unpinned .mcp.json:3
  github               stdio    docker                       unpinned .mcp.json:4

Tool Capabilities (6 classified tools)
  code_execution           1  ShellTool
  external_side_effect     3  GmailToolkit, ShellTool, @modelcontextprotocol/server-filesystem
  model_call               1  ChatOpenAI
  sensitive_data_access    2  GmailToolkit, @modelcontextprotocol/server-filesystem
  untrusted_content_in     3  TavilySearchResults, GmailToolkit, mcp-server-fetch
```

The "Codebase combines" finding is the one I care about most. An agent that reads content from strangers, can reach
private data and can act on the outside world is the setup that makes prompt injection dangerous. The JSON output
names the tools behind each leg, so you can see which one to take away.

## New in 1.3

- **MCP server inventory.** Every MCP server in the repo, one row each: how it is launched, its transport, whether
  the version is pinned, and the file and line. Read from MCP config files in any repo and from Python code.
- **Agent tool capabilities.** About 500 LangChain and CrewAI tools and 16 common MCP servers are classed by what they
  can do: read untrusted content, reach sensitive data, act on the outside world, run code.
- **A finding for the dangerous combination.** HIGH when one module holds all three legs, MEDIUM when they are spread
  across files or only listed in a config file.
- **OWASP mappings.** Findings link to the OWASP Top 10 for LLM Applications (2025) and the OWASP Top 10 for Agentic
  Applications (2026). The nine items a static scan cannot see are reported as GAP, not hidden.
- **Hardcoded keys stay out of the report.** 1.2.0 wrote the full value of a hardcoded key into the JSON output.
  1.3.0 does not, and it masks key-shaped strings in quoted code lines. A 1.2.0 JSON report that found a hardcoded
  key holds that key.

Full detail is in the [changelog](CHANGELOG.md).

## What It Finds

`aibom-scanner` detects AI SDKs in your codebase and generates an **AI Bill of Materials (AIBOM)** with compliance risk findings mapped to three compliance frameworks and two OWASP lists.

| | |
|---|---|
| **70 detection patterns** | OpenAI, Anthropic, Google AI, AWS Bedrock, Cohere, Mistral, Groq, HuggingFace, and 21 more |
| **Languages** | Python, JS/TS, Go, Java, Rust, Ruby, Swift, C#/.NET — imports, API calls, and dependency manifests |
| **10 Chinese AI providers** | 3 BIS Entity-Listed (Zhipu, iFlytek, SenseTime = CRITICAL), 7 data sovereignty flagged |
| **Agentic AI detection** | CrewAI, AutoGen, LangGraph, Semantic Kernel, MCP |
| **MCP servers** | Listed one by one from config files and Python code: transport, launch command, pinned or not |
| **Agent tool capabilities** | About 500 LangChain and CrewAI tools and 16 MCP servers, in five capability classes |
| **34 risk rules** | 8 categories with evidence-qualified severity adjustment |
| **49 compliance controls** | NIST AI RMF (23), ISO 42001 (15), EU AI Act (11) |
| **20 OWASP items** | OWASP LLM Top 10 (2025) and OWASP Agentic Top 10 (2026), reported as MAPPED, PARTIAL or GAP; 9 have no static signal and always read GAP (see below) |
| **Secrets detection** | Hardcoded API keys, Vault, AWS Secrets Manager, dotenv |
| **Dev tool detection** | Cursor, GitHub Copilot, Claude Code, Aider, TabNine |
| **Coverage accounting** | Every scan reports what it read — and what it could not |
| **Zero dependencies** | Pure Python stdlib. Nothing to install but Python. |

## MCP server inventory

The JSON output lists each MCP server in `mcp_servers`: name, transport (stdio, sse, http, hosted), command, args,
URL host, env and header key names, source file and line, and whether an `npx`, `uvx`, `pipx run` or `docker run`
command is version-pinned. Servers come from `mcp.json`, `.mcp.json`, `mcp_config.json` and `claude_desktop_config.json`
files and from Python code. Values are never stored: env and header entries are key names only, URLs are reduced to
scheme and host, and `args` is an allowlist: flag names, the package or image of an `npx`, `uvx`,
`pipx run` or `docker run` command, and `--flag=<redacted>`. Every other argument, including paths and flag
values, is shown as `<arg>`. Servers defined in C#, TypeScript or Go
source are not listed per server; `summary.mcp_servers_note` says so.

## Tool capability classes

Tools an agent can call are classed as `untrusted_content_in`, `sensitive_data_access`, `external_side_effect`,
`code_execution` or `model_call`, in `tool_capabilities` and `summary.capability_classes`. Python tools are matched
by import against a table of about 500 LangChain and CrewAI tools. MCP servers are classed only when their package
(version stripped) is in a short table; others get no class and are never guessed from their name. A codebase that holds
untrusted input, sensitive data access and an action capability (external side effect or code execution) gets the HIGH
finding "Codebase combines untrusted input, sensitive data access and an action capability", with the tools as evidence.
It is HIGH when one Python module holds the three legs in at least two distinct tools (at least one found by import),
because those tools are available to the same module. Servers listed only in an MCP config file give MEDIUM: a config
file shows availability, not use. It is also MEDIUM when the legs are spread across files, because they may
belong to different agents. A short list of web search, scrape and browser
SDKs (for example `tavily`, `firecrawl`, `playwright`) also counts as `untrusted_content_in`, matched by import.
Tools that are not in the tables are not classified.

## OWASP mappings

Findings link to the OWASP Top 10 for LLM Applications (2025, `OWASP-LLM01`..`10`) and the OWASP Top 10 for Agentic
Applications (2026, `OWASP-ASI01`..`10`). Eleven items are reachable by a finding today (LLM01, 02, 03, 05, 06 and
ASI01, 02, 03, 04, 05, 09). Nine have no static signal and are reported as GAP, never hidden: LLM04 Data and Model
Poisoning, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded
Consumption, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures
and ASI10 Rogue Agents. A reachable item is PARTIAL when a finding points at it: the scanner reports a risk signal,
not proof that a control is in place. JSON shows all 20; SARIF shows the linked ids as rule tags; the table shows
the first three references per finding.

Two findings added with the mappings: "MCP server launched without a pinned version" and "Agent tool can execute code".

## Coverage: what the scan actually read

An AI Bill of Materials that silently omits what it could not parse is not
incomplete, it is wrong. Every scan reports its own denominator:

```
Scanned 86 of 173 source files (49.7%) — 86 test/fixture files excluded, 98.9% of source attempted
```

Two ratios, because either one alone misleads:

| Field | Meaning |
|---|---|
| `coverage_pct` | `files_scanned / source_files_seen` — the honest headline. Every source file in the tree is in the denominator. |
| `readable_coverage_pct` | `files_scanned / (source_files_seen - skipped_by_path)` — isolates scanner capability from the tests and fixtures deliberately excluded. |

Quoting only the second would report ~99% for a scan that read half a repo.

Every unread source file is attributed to exactly one reason:

- **`skipped_by_path`** — intentional exclusion (tests, fixtures, examples, vendor).
- **`unscanned_by_extension`** — this scanner version cannot parse the language.

**Languages the scanner cannot read are reported, never treated as clean.** When any
turn up, a warning is printed to stderr, the table output shows an `INCOMPLETE
COVERAGE` block, and SARIF carries a `toolExecutionNotification` so the run reads as
partial rather than silently green. Currently unreadable: `.php`, `.scala`, `.clj`,
`.ex`, `.exs`, `.dart`, `.cpp`, `.c`, `.h`, `.hpp`, `.m`, `.mm`, `.pl`, `.lua`, `.r`,
`.jl`, `.ps1`, `.kts`.

## Observed vs inferred findings

Every finding carries an `evidence_basis`:

- **`observed`** — backed by something in the scanned source (a detection, a provider).
- **`inferred`** — a governance checklist item. Nothing in the source backs it.

Inferred findings reflect *absence of evidence, not evidence of absence*. Table output
separates them into their own section, `--severity-threshold` ignores them, and SARIF
does not emit them as code-scanning alerts — a governance checklist item is not a
defect at a code location.

## Output Formats

```bash
# Table output (default in terminal)
aibom-scanner scan --path . --format table

# JSON (default when piped) — includes coverage and evidence_basis
aibom-scanner scan --path . --format json > aibom.json

# SARIF for GitHub Code Scanning — observed findings only, coverage in run properties
aibom-scanner scan --path . --format sarif > results.sarif

# Fail CI on high/critical OBSERVED findings (exit 1)
aibom-scanner scan --path . --severity-threshold high

# Fail CI when the scanner could not read some languages (exit 3)
aibom-scanner scan --path . --fail-on-incomplete-coverage
```

| Exit code | Meaning |
|:---:|---|
| `0` | Scan completed, no gate tripped |
| `1` | Observed findings at or above `--severity-threshold` |
| `2` | Bad arguments, unreadable path, or interrupted |
| `3` | `--fail-on-incomplete-coverage` set and languages were unreadable |

If both gates trip, `1` wins — an observed finding is more actionable than a coverage gap.

The coverage warning always goes to **stderr**, so piping `--format json` or
`--format sarif` to a file yields clean, valid output.

## GitHub Action

Add AI compliance scanning to every PR:

```yaml
# .github/workflows/aibom-scan.yml
name: AIBOM Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: saasvista/aibom-scanner@v1.3.2
        with:
          severity-threshold: high
```

## AI Providers Detected

| Category | Providers |
|----------|-----------|
| **Major** | OpenAI, Anthropic, Google AI, AWS Bedrock, Azure OpenAI, Cohere, Mistral, Groq |
| **Open Source** | HuggingFace, Together AI, Fireworks, Replicate |
| **Chinese (BIS Entity List)** | Zhipu AI, iFlytek, SenseTime |
| **Chinese (Data Sovereignty)** | DeepSeek, Alibaba Qwen, Baidu ERNIE, Moonshot, MiniMax, Baichuan, Yi |
| **Agentic** | CrewAI, AutoGen, LangGraph, Semantic Kernel |
| **Protocol** | MCP (Model Context Protocol), with each configured server listed |
| **Orchestration** | LangChain, LlamaIndex |

## Risk Categories

| Category | Rules | Examples |
|----------|:-----:|---------|
| Data Privacy | 4 | Missing DPA, data classification, prompt retention |
| Model Governance | 8 | No inventory, no versioning, supply chain risk |
| Security | 4 | Hardcoded keys, no input/output validation |
| Transparency | 3 | No AI disclosure, no decision logging |
| Accountability | 3 | No risk owner, no incident response plan |
| Bias & Fairness | 2 | No bias testing, no fairness evaluation |
| Export Compliance | 4 | BIS Entity List, data sovereignty, EU AI Act |
| Agentic AI | 5 | No HITL, no access controls, no observability |

Three more findings are built from evidence, not from a provider rule: the combined-capability finding, the
unpinned MCP server and the agent tool that can execute code.

## Compliance Frameworks

| Framework | Controls | Coverage |
|-----------|:--------:|----------|
| **NIST AI RMF** | 23 | GOVERN, MAP, MEASURE, MANAGE functions |
| **ISO 42001** | 15 | AI management system requirements |
| **EU AI Act** | 11 | Articles 5-52, high-risk classification |
| **OWASP LLM Top 10 (2025)** | 10 | LLM01 to LLM10; 5 reachable by a finding |
| **OWASP Agentic Top 10 (2026)** | 10 | ASI01 to ASI10; 6 reachable by a finding |

## Why This Exists

We scanned 5 popular open-source AI repos (470K combined GitHub stars):

- **389** AI SDK detections
- **116** compliance findings
- **0** governance controls fully mapped

One enterprise security company had a **BIS Entity-Listed Chinese AI provider** inherited silently through an acquisition.

If you don't know which AI SDKs, MCP servers and agent tools are in your codebase, you can't govern them.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- **Add detection patterns** — new AI providers, SDKs, or frameworks
- **Improve risk rules** — better severity calibration, new categories
- **New output formats** — CycloneDX, SPDX, HTML reports
- **Language support** — Go, Rust, Java detection improvements

## License

Apache-2.0. See [LICENSE](LICENSE).

---

<p align="center">
  Built by <a href="https://saasvista.io">SaaSVista</a> — AI Risk & Compliance Copilot
</p>
