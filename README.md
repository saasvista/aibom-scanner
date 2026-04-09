# aibom-scanner

Scan codebases for AI SDK usage. Map compliance risks to NIST AI RMF, ISO 42001, and EU AI Act.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-43%20passing-green.svg)]()

## What it does

`aibom-scanner` detects AI SDKs in your codebase and generates an **AI Bill of Materials (AIBOM)** with compliance risk findings.

- **61 detection patterns** across 30+ AI providers (OpenAI, Anthropic, Google AI, AWS Bedrock, Cohere, Mistral, Groq, HuggingFace, and more)
- **10 Chinese AI providers** with US BIS Entity List flagging (Zhipu, iFlytek, SenseTime = CRITICAL)
- **Agentic AI** detection (CrewAI, AutoGen, LangGraph, Semantic Kernel, MCP)
- **34 risk rules** across 8 categories with evidence-qualified severity
- **48 compliance controls** mapped to NIST AI RMF (23), ISO 42001 (15), EU AI Act (10)
- **Secrets detection** — hardcoded API keys, Vault, AWS Secrets Manager, dotenv patterns
- **Dev tool detection** — Cursor, GitHub Copilot, Claude Code, Aider, TabNine, Codeium
- **Zero dependencies** — pure Python stdlib

## Quick start

```bash
pip install aibom-scanner

# Scan a directory
aibom-scanner scan --path /path/to/your/repo

# JSON output
aibom-scanner scan --path . --format json > aibom.json

# Fail CI on high/critical findings
aibom-scanner scan --path . --severity-threshold high
```

## Sample output

```
AIBOM Scanner Results
──────────────────────────────────────────────────────────────────────
  Scanned 247 files
  Found 33 AI SDK detections + 8 dependency detections
  Providers: openai (12), anthropic (8), deepseek (5), zhipu (3), langchain (3), mcp (2)

Risk Findings (9)
──────────────────────────────────────────────────────────────────────
  CRITICAL: 1
  HIGH: 4
  MEDIUM: 3
  LOW: 1

  [CRITICAL] US Entity List violation — prohibited Chinese AI provider
             Providers: zhipu
             Frameworks: NIST-GOVERN-1.6, ISO-42001-A.7.3, EU-AI-ACT-ART-5

  [HIGH    ] Chinese AI provider — data sovereignty risk
             Providers: deepseek
             Frameworks: NIST-GOVERN-1.6, ISO-42001-A.7.5, EU-AI-ACT-ART-10

  [HIGH    ] AI model usage without governance framework
             Providers: openai, anthropic, deepseek, zhipu, langchain, mcp
             Frameworks: NIST-GOVERN-1.1, ISO-42001-5.1, EU-AI-ACT-ART-9
  ...
```

## Output formats

| Format | Use case | Flag |
|--------|----------|------|
| **table** | Terminal (default) | `--format table` |
| **json** | Programmatic processing | `--format json` |
| **sarif** | GitHub Code Scanning | `--format sarif` |

## GitHub Action

Add AI compliance scanning to your CI pipeline:

```yaml
# .github/workflows/aibom-scan.yml
name: AIBOM Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: saasvista/aibom-scanner@v1
        with:
          severity-threshold: high
```

## What it detects

### AI Providers (30+)

| Category | Providers |
|----------|-----------|
| **Major** | OpenAI, Anthropic, Google AI, AWS Bedrock, Azure OpenAI, Cohere, Mistral, Groq |
| **Open Source** | HuggingFace, Together AI, Fireworks, Replicate |
| **Chinese (BIS Entity List)** | Zhipu AI, iFlytek, SenseTime |
| **Chinese (Data Sovereignty)** | DeepSeek, Alibaba Qwen, Baidu ERNIE, Moonshot, MiniMax, Baichuan, Yi |
| **Agentic** | CrewAI, AutoGen, LangGraph, Semantic Kernel |
| **Protocol** | MCP (Model Context Protocol) |
| **Orchestration** | LangChain, LlamaIndex |

### Risk Categories (8)

| Category | Rules | Example |
|----------|-------|---------|
| Data Privacy | 4 | Missing DPA, data classification, prompt retention |
| Model Governance | 8 | No inventory, no versioning, supply chain risk |
| Security | 4 | Hardcoded keys, no input/output validation |
| Transparency | 3 | No AI disclosure, no decision logging |
| Accountability | 3 | No risk owner, no incident response plan |
| Bias & Fairness | 2 | No bias testing, no fairness evaluation |
| Compliance | 4 | BIS Entity List, data sovereignty, EU AI Act |
| Agentic AI | 5 | No HITL, no access controls, no observability |

### Compliance Frameworks (3)

| Framework | Controls | Coverage |
|-----------|----------|----------|
| **NIST AI RMF** | 23 | GOVERN, MAP, MEASURE, MANAGE functions |
| **ISO 42001** | 15 | AI management system requirements |
| **EU AI Act** | 10 | Articles 5-52, high-risk classification |

## How it works

```
Your Codebase → File Walker → AI SDK Detector → Risk Engine → Control Mapper → Output
                    ↓              ↓                 ↓              ↓
               git ls-files   61 regex patterns   34 rules      48 controls
               os.walk        model extraction    8 categories   3 frameworks
                              dependency scan     evidence qual  gap analysis
                              secrets detection   consolidation
```

1. **Walk** — Lists files via `git ls-files` (or `os.walk` for non-git dirs)
2. **Detect** — Matches 61 patterns for AI imports, API calls, configs, and dependencies
3. **Classify** — Applies 34 risk rules with severity and evidence qualification
4. **Consolidate** — Merges related findings into actionable risk groups
5. **Map** — Maps risks to 48 controls across NIST AI RMF, ISO 42001, and EU AI Act

## Why this exists

We scanned 5 popular open-source AI repos (470K combined GitHub stars). Found 389 AI SDK detections, 116 compliance findings, and zero governance controls fully mapped in any of them. One enterprise security company had a BIS Entity-Listed Chinese AI provider inherited silently through an acquisition.

EU AI Act enforcement starts August 2026. Enterprise buyers are asking AI governance questions in every procurement questionnaire. If you don't know what AI SDKs are in your codebase, you can't answer them.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- **Add detection patterns** — new AI providers, SDKs, or frameworks
- **Improve risk rules** — better severity calibration, new categories
- **New output formats** — CycloneDX, SPDX, HTML reports
- **Language support** — Go, Rust, Java detection improvements

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Built by [SaaSVista](https://saasvista.io) — AI Risk & Compliance Copilot.
