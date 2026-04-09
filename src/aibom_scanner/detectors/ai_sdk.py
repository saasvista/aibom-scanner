"""Detect AI SDK imports, usage patterns, model names, and dependencies in source code."""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Detection:
    provider: str
    sdk_name: str
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float
    detection_type: str  # "import", "api_call", "config", "dependency"
    model_name: Optional[str] = None
    version: Optional[str] = None


# Patterns: (provider, sdk_name, regex_pattern, detection_type)
AI_SDK_PATTERNS = [
    # OpenAI
    ("openai", "openai", r"(?:from\s+openai|import\s+openai|require\(['\"]openai['\"]|from\s+['\"]openai['\"])", "import"),
    ("openai", "openai", r"OpenAI\(\)|openai\.ChatCompletion|openai\.Completion|client\.chat\.completions", "api_call"),
    # Anthropic
    ("anthropic", "anthropic", r"(?:from\s+anthropic|import\s+anthropic|require\(['\"]@anthropic-ai|from\s+['\"]@anthropic-ai)", "import"),
    ("anthropic", "anthropic", r"Anthropic\(\)|client\.messages\.create|anthropic\.messages", "api_call"),
    # AWS Bedrock
    ("aws_bedrock", "boto3", r"bedrock-runtime|bedrock\.invoke_model|BedrockRuntime", "api_call"),
    # Google AI
    ("google_ai", "google-generativeai", r"(?:from\s+google\.generativeai|import\s+google\.generativeai|@google/generative-ai)", "import"),
    ("google_ai", "vertex-ai", r"(?:from\s+vertexai|aiplatform)", "import"),
    # Azure OpenAI
    ("azure_openai", "openai", r"AzureOpenAI\(|azure\.openai|AZURE_OPENAI", "api_call"),
    # Hugging Face — require word boundaries and specific suffixes to reduce false positives
    ("huggingface", "transformers", r"(?:from\s+transformers\b|import\s+transformers\b)", "import"),
    ("huggingface", "transformers", r"(?:Auto(?:Model|Tokenizer)(?:ForCausalLM|ForSeq2Seq|ForSequenceClassification|ForTokenClassification|ForQuestionAnswering|\.from_pretrained))", "import"),
    ("huggingface", "transformers", r"(?:from\s+transformers\b.*import.*pipeline|transformers\.pipeline\(|pipeline\(\s*[\"'](?:text-|token-|question-|summarization|translation|fill-mask|image-|audio-|zero-shot|feature-extraction|sentiment))", "api_call"),
    # Cohere
    ("cohere", "cohere", r"(?:from\s+cohere|import\s+cohere|require\(['\"]cohere['\"])", "import"),
    # LangChain
    ("langchain", "langchain", r"(?:from\s+langchain|import\s+langchain|@langchain)", "import"),
    # LlamaIndex
    ("llamaindex", "llama-index", r"(?:from\s+llama_index|import\s+llama_index)", "import"),
    # Replicate
    ("replicate", "replicate", r"(?:from\s+replicate|import\s+replicate|require\(['\"]replicate['\"])", "import"),
    ("replicate", "replicate", r"replicate\.run\(|replicate\.models", "api_call"),
    # Together AI
    ("together_ai", "together", r"(?:from\s+together|import\s+together|require\(['\"]together-ai['\"])", "import"),
    ("together_ai", "together", r"Together\(\)|together\.chat\.completions", "api_call"),
    # Mistral
    ("mistral", "mistral", r"(?:from\s+mistralai|import\s+mistralai|require\(['\"]@mistralai)", "import"),
    ("mistral", "mistral", r"MistralClient\(|Mistral\(|mistral\.chat", "api_call"),
    # Groq
    ("groq", "groq", r"(?:from\s+groq|import\s+groq|require\(['\"]groq-sdk['\"])", "import"),
    ("groq", "groq", r"Groq\(\)|groq\.chat\.completions", "api_call"),
    # Fireworks
    ("fireworks", "fireworks-ai", r"(?:from\s+fireworks|import\s+fireworks|require\(['\"]@fireworks-ai)", "import"),
    ("fireworks", "fireworks-ai", r"Fireworks\(\)|fireworks\.chat\.completions", "api_call"),
    # --- Chinese AI Providers ---
    # Zhipu AI (GLM) — US BIS Entity List (Jan 16, 2025, 10 subsidiaries)
    ("zhipu", "zhipuai", r"(?:from\s+zhipuai|import\s+zhipuai)", "import"),
    ("zhipu", "zhipuai", r"ZhipuAI\(\)|zhipuai\.model_api|zhipu_api_key", "api_call"),
    ("zhipu", "zhipuai", r"open\.bigmodel\.cn", "api_call"),
    # iFlytek (科大讯飞) — US BIS Entity List (Oct 9, 2019, Footnote 4)
    ("iflytek", "iflytek", r"(?:from\s+iflytek|import\s+iflytek|from\s+sparkai|import\s+sparkai)", "import"),
    ("iflytek", "iflytek", r"IFLYTEK_API_KEY|SPARK_API_KEY|spark-api\.xf-yun\.com|SparkApi", "api_call"),
    ("iflytek", "iflytek", r"iflytek\.open|iflytek_spark|xf-yun\.com", "api_call"),
    # SenseTime (商汤科技) — US BIS Entity List (Oct 9, 2019) + 1260H (Jan 2025)
    ("sensetime", "sensetime", r"(?:from\s+sensetime|import\s+sensetime|from\s+sensenova|import\s+sensenova)", "import"),
    ("sensetime", "sensetime", r"SENSETIME_API_KEY|SENSENOVA_API_KEY|api\.sensenova\.cn|SenseNovaClient", "api_call"),
    # Alibaba Qwen (DashScope)
    ("alibaba_qwen", "dashscope", r"(?:from\s+dashscope|import\s+dashscope)", "import"),
    ("alibaba_qwen", "dashscope", r"dashscope\.Generation|dashscope\.TextGeneration|DASHSCOPE_API_KEY", "api_call"),
    ("alibaba_qwen", "dashscope", r"dashscope(?:-intl)?\.aliyuncs\.com", "api_call"),
    # Baidu ERNIE (Qianfan)
    ("baidu_ernie", "qianfan", r"(?:from\s+qianfan|import\s+qianfan)", "import"),
    ("baidu_ernie", "qianfan", r"qianfan\.ChatCompletion|qianfan\.Completion|QIANFAN_", "api_call"),
    ("baidu_ernie", "qianfan", r"aistudio\.baidu\.com|qianfan\.baidubce\.com", "api_call"),
    # DeepSeek
    ("deepseek", "deepseek", r"(?:from\s+deepseek|import\s+deepseek)", "import"),
    ("deepseek", "deepseek", r"DEEPSEEK_API_KEY|api\.deepseek\.com", "api_call"),
    # Moonshot / Kimi
    ("moonshot", "moonshot", r"(?:from\s+moonshot|import\s+moonshot)", "import"),
    ("moonshot", "moonshot", r"MOONSHOT_API_KEY|api\.moonshot\.cn", "api_call"),
    # MiniMax
    ("minimax", "minimax", r"(?:from\s+minimax|import\s+minimax)", "import"),
    ("minimax", "minimax", r"MINIMAX_API_KEY|api\.minimax\.chat|MiniMaxClient", "api_call"),
    # Baichuan
    ("baichuan", "baichuan", r"(?:from\s+baichuan|import\s+baichuan)", "import"),
    ("baichuan", "baichuan", r"BAICHUAN_API_KEY|api\.baichuan-ai\.com|BaichuanClient", "api_call"),
    # 01.AI (Yi)
    ("yi", "yi", r"api\.lingyiwanwu\.com|YI_API_KEY", "api_call"),
    # Chinese AI via OpenAI-compatible endpoints (base_url detection)
    ("deepseek", "openai-compat", r"base_url\s*=\s*['\"]https?://api\.deepseek\.com", "api_call"),
    ("moonshot", "openai-compat", r"base_url\s*=\s*['\"]https?://api\.moonshot\.cn", "api_call"),
    ("yi", "openai-compat", r"base_url\s*=\s*['\"]https?://api\.lingyiwanwu\.com", "api_call"),
    ("zhipu", "openai-compat", r"base_url\s*=\s*['\"]https?://open\.bigmodel\.cn", "api_call"),
    # --- Agentic AI Frameworks ---
    # CrewAI
    ("crewai", "crewai", r"(?:from\s+crewai|import\s+crewai)", "import"),
    ("crewai", "crewai", r"(?:Crew\(\s*|\.kickoff\(|process\s*=\s*Process\.)", "api_call"),
    # AutoGen (Microsoft)
    ("autogen", "autogen", r"(?:from\s+autogen|import\s+autogen|from\s+pyautogen|import\s+pyautogen)", "import"),
    ("autogen", "autogen", r"(?:AssistantAgent\(|UserProxyAgent\(|GroupChat\(|ConversableAgent\()", "api_call"),
    # LangGraph
    ("langgraph", "langgraph", r"(?:from\s+langgraph|import\s+langgraph)", "import"),
    ("langgraph", "langgraph", r"(?:StateGraph\(|MessageGraph\(|add_node\(|add_edge\(|add_conditional_edges\()", "api_call"),
    # Semantic Kernel (Microsoft)
    ("semantic_kernel", "semantic-kernel", r"(?:from\s+semantic_kernel|import\s+semantic_kernel)", "import"),
    ("semantic_kernel", "semantic-kernel", r"(?:Kernel\(\)|kernel\.add_plugin|kernel\.invoke|KernelFunction)", "api_call"),
    # --- Model Context Protocol (MCP) ---
    ("mcp", "mcp", r"(?:from\s+mcp|import\s+mcp)", "import"),
    ("mcp", "mcp", r"(?:FastMCP\(|mcp\.server|mcp\.client|StdioServerTransport|SSEServerTransport|StreamableHTTPServerTransport)", "api_call"),
]


# Model name extraction patterns: (regex, group_index)
MODEL_PATTERNS = [
    # OpenAI models
    (r"""['\"]+(gpt-4[a-z0-9\-]*)['\"]""", 1),
    (r"""['\"]+(gpt-3\.5[a-z0-9\-]*)['\"]""", 1),
    (r"""['\"]+(o[1-9][a-z0-9\-]*)['\"]""", 1),  # o1, o3, etc.
    (r"""['\"]+(davinci[a-z0-9\-]*)['\"]""", 1),
    # Anthropic models
    (r"""['\"]+(claude-[a-z0-9\.\-]+)['\"]""", 1),
    # Google models
    (r"""['\"]+(gemini-[a-z0-9\.\-]+)['\"]""", 1),
    (r"""['\"]+(palm-[a-z0-9\.\-]+)['\"]""", 1),
    # Mistral models
    (r"""['\"]+(mistral-[a-z0-9\.\-]+)['\"]""", 1),
    (r"""['\"]+(mixtral-[a-z0-9\.\-]+)['\"]""", 1),
    # Meta models
    (r"""['\"]+(llama-[a-z0-9\.\-]+)['\"]""", 1),
    (r"""['\"]+(llama[23][a-z0-9\.\-]*)['\"]""", 1),
    # Chinese AI models
    (r"""['\"]+(deepseek-(?:chat|coder|reasoner|v[0-9])[a-z0-9\.\-]*)['\"]""", 1),
    (r"""['\"]+(qwen-?[a-z0-9\.\-]+)['\"]""", 1),
    (r"""['\"]+(ernie-?[a-z0-9\.\-]+)['\"]""", 1),
    (r"""['\"]+(glm-?[0-9][a-z0-9\.\-]*)['\"]""", 1),
    (r"""['\"]+(moonshot-v[0-9][a-z0-9\.\-]*)['\"]""", 1),
    (r"""['\"]+(yi-[a-z0-9\.\-]+)['\"]""", 1),
    (r"""['\"]+(baichuan[0-9]-?[a-z0-9\.\-]*)['\"]""", 1),
    (r"""['\"]+(abab[0-9][a-z0-9\.\-]*)['\"]""", 1),  # MiniMax model names
    (r"""['\"]+(spark-?[a-z0-9\.\-]+)['\"]""", 1),  # iFlytek Spark models
    (r"""['\"]+(sensenova-?[a-z0-9\.\-]+)['\"]""", 1),  # SenseTime SenseNova models
    # Generic model= param
    (r"""model\s*=\s*['\"]([a-zA-Z0-9\-\.\/\:]+)['\"]""", 1),
]


# Dependency file patterns: package_name -> provider
DEPENDENCY_MAP = {
    # Python packages
    "openai": "openai",
    "anthropic": "anthropic",
    "google-generativeai": "google_ai",
    "google-cloud-aiplatform": "google_ai",
    "vertexai": "google_ai",
    "boto3": "aws_bedrock",
    "transformers": "huggingface",
    "cohere": "cohere",
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-openai": "langchain",
    "langchain-anthropic": "langchain",
    "langchain-community": "langchain",
    "llama-index": "llamaindex",
    "llama-index-core": "llamaindex",
    "replicate": "replicate",
    "together": "together_ai",
    "mistralai": "mistral",
    "groq": "groq",
    "fireworks-ai": "fireworks",
    # Chinese AI provider packages
    "zhipuai": "zhipu",
    "sparkai": "iflytek",
    "iflytek-spark": "iflytek",
    "sensetime": "sensetime",
    "sensenova": "sensetime",
    "dashscope": "alibaba_qwen",
    "qianfan": "baidu_ernie",
    "deepseek": "deepseek",
    "moonshot": "moonshot",
    "minimax": "minimax",
    "baichuan": "baichuan",
    # Agentic AI framework packages
    "crewai": "crewai",
    "crewai-tools": "crewai",
    "pyautogen": "autogen",
    "autogen-agentchat": "autogen",
    "autogen-core": "autogen",
    "autogen-ext": "autogen",
    "langgraph": "langgraph",
    "langgraph-checkpoint": "langgraph",
    "semantic-kernel": "semantic_kernel",
    # MCP packages
    "mcp": "mcp",
    "fastmcp": "mcp",
    # npm packages
    "@openai/api": "openai",
    "@anthropic-ai/sdk": "anthropic",
    "@google/generative-ai": "google_ai",
    "@mistralai/mistralai": "mistral",
    "groq-sdk": "groq",
    "@fireworks-ai/client": "fireworks",
    "together-ai": "together_ai",
    "cohere-ai": "cohere",
    "@langchain/core": "langchain",
    "@langchain/openai": "langchain",
    "@langchain/anthropic": "langchain",
    "@langchain/langgraph": "langgraph",
    "llamaindex": "llamaindex",
    "autogen": "autogen",
    "@modelcontextprotocol/sdk": "mcp",
}


def _extract_model_name(lines: list[str], line_idx: int, context_window: int = 5) -> str | None:
    """Extract AI model name from current line or nearby context (Task 1.3)."""
    # Check current line first, then nearby lines
    start = max(0, line_idx - context_window)
    end = min(len(lines), line_idx + context_window + 1)
    search_lines = [lines[line_idx]] + [lines[i] for i in range(start, end) if i != line_idx]

    for search_line in search_lines:
        for mp, group in MODEL_PATTERNS:
            match = re.search(mp, search_line, re.IGNORECASE)
            if match:
                return match.group(group)
    return None


def scan_file(file_path: str, content: str) -> list[Detection]:
    """Scan a file's content for AI SDK usage patterns.

    Includes deduplication: one entry per (provider, file_path, detection_type)
    unless different model_names are found (Task 1.2).
    """
    raw_detections = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, start=1):
        for provider, sdk_name, pattern, det_type in AI_SDK_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                model_name = _extract_model_name(lines, line_num - 1)

                raw_detections.append(Detection(
                    provider=provider,
                    sdk_name=sdk_name,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip()[:500],
                    confidence=0.9,
                    detection_type=det_type,
                    model_name=model_name,
                ))

    # Deduplicate: keep one entry per (provider, detection_type, model_name)
    # Use lowest line number for each group
    seen: dict[tuple, Detection] = {}
    for d in raw_detections:
        key = (d.provider, d.detection_type, d.model_name or "")
        if key not in seen or d.line_number < seen[key].line_number:
            seen[key] = d

    return list(seen.values())


def scan_dependencies(file_path: str, content: str) -> list[dict]:
    """Scan a dependency file for AI SDK packages. Returns list of dicts with package, version, provider, source_file."""
    results = []
    filename = file_path.split("/")[-1] if "/" in file_path else file_path

    if filename == "requirements.txt":
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Parse: package==version, package>=version, package
            match = re.match(r'^([a-zA-Z0-9\-_\.]+)\s*(?:[><=!~]+\s*([0-9][a-zA-Z0-9\.\-\*]*))?', line)
            if match:
                pkg = match.group(1).lower()
                ver = match.group(2)
                if pkg in DEPENDENCY_MAP:
                    results.append({"package": pkg, "version": ver, "provider": DEPENDENCY_MAP[pkg], "source_file": file_path})

    elif filename == "package.json":
        import json
        try:
            data = json.loads(content)
            for section in ["dependencies", "devDependencies"]:
                deps = data.get(section, {})
                for pkg, ver in deps.items():
                    pkg_lower = pkg.lower()
                    if pkg_lower in DEPENDENCY_MAP:
                        # Clean version string (remove ^, ~, etc.)
                        clean_ver = re.sub(r'^[\^~>=<]+', '', str(ver))
                        results.append({"package": pkg, "version": clean_ver, "provider": DEPENDENCY_MAP[pkg_lower], "source_file": file_path})
        except json.JSONDecodeError:
            pass

    elif filename in ("Pipfile", "pyproject.toml"):
        # Simple TOML-like parsing for package names
        for line in content.split("\n"):
            line = line.strip()
            for pkg in DEPENDENCY_MAP:
                if pkg in line.lower():
                    ver_match = re.search(r'["\']([0-9][a-zA-Z0-9\.\-\*]*)["\']', line)
                    results.append({"package": pkg, "version": ver_match.group(1) if ver_match else None, "provider": DEPENDENCY_MAP[pkg], "source_file": file_path})

    elif filename == "go.mod":
        for line in content.split("\n"):
            line = line.strip()
            # Look for known Go AI packages
            go_ai_pkgs = {
                "github.com/sashabaranov/go-openai": "openai",
                "github.com/anthropics/anthropic-sdk-go": "anthropic",
                "github.com/mark3labs/mcp-go": "mcp",
            }
            for go_pkg, provider in go_ai_pkgs.items():
                if go_pkg in line:
                    ver_match = re.search(r'v([0-9][a-zA-Z0-9\.\-]*)', line)
                    results.append({"package": go_pkg, "version": ver_match.group(1) if ver_match else None, "provider": provider, "source_file": file_path})

    elif filename == "Cargo.toml":
        for line in content.split("\n"):
            line = line.strip()
            cargo_ai_pkgs = {"async-openai": "openai"}
            for pkg, provider in cargo_ai_pkgs.items():
                if pkg in line.lower():
                    ver_match = re.search(r'"([0-9][a-zA-Z0-9\.\-]*)"', line)
                    results.append({"package": pkg, "version": ver_match.group(1) if ver_match else None, "provider": provider, "source_file": file_path})

    return results


# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs",
    ".java", ".kt", ".go", ".rs", ".rb",
    ".yaml", ".yml", ".toml",
}

# JSON scanned separately — only in config-like locations, not data directories
JSON_SCANNABLE = {".json"}

# Path segments that indicate non-production code (test, fixture, data, docs, archives)
SKIP_PATH_SEGMENTS = {
    "test", "tests", "testing", "__tests__", "__test__",
    "spec", "specs", "__spec__",
    "fixture", "fixtures", "__fixtures__",
    "mock", "mocks", "__mocks__",
    "example", "examples",
    "node_modules", ".next", "dist", "build", ".git",
    "archives", "legacy-data",
    "vendor", "third_party", "third-party",
}

# Path prefixes for data directories (matched against start of segments)
SKIP_DATA_PATHS = {
    "public/data",
    "data/apps",
    "data/raw",
}


# Guardrail detection patterns
GUARDRAIL_PATTERNS = [
    (re.compile(r'(validate_input|sanitize_input|input_validation|sanitize)', re.I), "input_sanitization"),
    (re.compile(r'(content_filter|moderate|moderation|safety_settings|safety_filter)', re.I), "content_filter"),
    (re.compile(r'(rate_limit|ratelimit|throttle|RateLimiter)', re.I), "rate_limiting"),
    (re.compile(r'(max_tokens|token_limit|max_length|truncat)', re.I), "token_limiting"),
    (re.compile(r'(output_validation|validate_output|response_validation|check_output)', re.I), "output_validation"),
    (re.compile(r'(guardrail|guard_rail|safety_check|content_safety|content_policy)', re.I), "guardrail"),
    (re.compile(r'(prompt_injection|injection_detect|injection_prevent)', re.I), "injection_defense"),
    (re.compile(r'(hallucination|fact_check|grounding|citation)', re.I), "factuality_check"),
]

# Transparency detection patterns
TRANSPARENCY_PATTERNS = [
    (re.compile(r'(ai.?generated|ai.?powered|ai.?assisted|generated.?by.?ai)', re.I), "ai_disclosure"),
    (re.compile(r'(ai.?disclosure|disclose.?ai|transparency.?notice)', re.I), "ai_disclosure"),
    (re.compile(r'(privacy.?policy|terms.?of.?service|data.?processing)', re.I), "privacy_policy"),
    (re.compile(r'(consent|opt.?out|opt.?in|user.?preference)', re.I), "user_consent"),
    (re.compile(r'(explainab|interpretab|model.?explain|feature.?importan)', re.I), "explainability"),
    (re.compile(r'(audit.?log|audit.?trail|decision.?log|ai.?log)', re.I), "audit_logging"),
]


# Human-in-the-loop detection patterns
HITL_PATTERNS = [
    (re.compile(r'(human.?in.?the.?loop|hitl|human.?review|human.?approval|human.?oversight)', re.I), "hitl_explicit"),
    (re.compile(r'(require.?approval|approval.?required|pending.?review|await.?human|manual.?review)', re.I), "approval_gate"),
    (re.compile(r'(escalat|fallback.?to.?human|human.?fallback|transfer.?to.?agent|hand.?off)', re.I), "escalation"),
    (re.compile(r'(confidence.?threshold|confidence.?score|uncertain|low.?confidence)', re.I), "confidence_gate"),
    (re.compile(r'(interrupt|breakpoint|checkpoint|pause.?execution|user.?confirm)', re.I), "execution_control"),
]


def scan_hitl(file_path: str, content: str) -> list[dict]:
    """Scan a file for human-in-the-loop patterns.

    Returns list of {pattern_type, file_path, line_number, snippet}.
    """
    results = []
    lines = content.split("\n")
    seen: set[str] = set()

    for line_num, line in enumerate(lines, start=1):
        for pattern, pattern_type in HITL_PATTERNS:
            if pattern.search(line) and pattern_type not in seen:
                seen.add(pattern_type)
                results.append({
                    "pattern_type": pattern_type,
                    "file_path": file_path,
                    "line_number": line_num,
                    "snippet": line.strip()[:200],
                })
    return results


def scan_guardrails(file_path: str, content: str) -> list[dict]:
    """Scan a file for guardrail implementation patterns.

    Returns list of {pattern_type, file_path, line_number, snippet}.
    """
    results = []
    lines = content.split("\n")
    seen: set[str] = set()

    for line_num, line in enumerate(lines, start=1):
        for pattern, pattern_type in GUARDRAIL_PATTERNS:
            if pattern.search(line) and pattern_type not in seen:
                seen.add(pattern_type)
                results.append({
                    "pattern_type": pattern_type,
                    "file_path": file_path,
                    "line_number": line_num,
                    "snippet": line.strip()[:200],
                })
    return results


def scan_transparency(file_path: str, content: str) -> list[dict]:
    """Scan a file for transparency implementation patterns.

    Returns list of {pattern_type, file_path, line_number, snippet}.
    """
    results = []
    lines = content.split("\n")
    seen: set[str] = set()

    for line_num, line in enumerate(lines, start=1):
        for pattern, pattern_type in TRANSPARENCY_PATTERNS:
            if pattern.search(line) and pattern_type not in seen:
                seen.add(pattern_type)
                results.append({
                    "pattern_type": pattern_type,
                    "file_path": file_path,
                    "line_number": line_num,
                    "snippet": line.strip()[:200],
                })
    return results


def classify_risk_tier(file_path: str, code_snippet: str = "") -> str:
    """Classify an AI detection as customer_facing, internal, or development.

    Classification based on file path segments and code context.
    """
    path_lower = file_path.lower()
    snippet_lower = code_snippet.lower()

    # Development tier — test/fixture/example/config paths
    dev_segments = {
        "test", "tests", "testing", "__tests__", "spec", "specs",
        "fixture", "fixtures", "mock", "mocks", "example", "examples",
        "scripts", "tools", "ci", ".github", "benchmark", "demo",
    }
    path_parts = set(path_lower.replace("\\", "/").split("/"))
    if path_parts & dev_segments:
        return "development"

    # Customer-facing tier — paths/snippets suggesting user exposure
    customer_indicators = {
        "api", "routes", "endpoints", "handlers", "controllers",
        "views", "pages", "components", "frontend", "public",
        "webhook", "chat", "conversation", "assistant",
    }
    customer_snippet_patterns = [
        "request.", "response.", "user_input", "user_message",
        "customer", "client_data", "pii", "personal_data",
    ]

    if path_parts & customer_indicators:
        return "customer_facing"
    if any(p in snippet_lower for p in customer_snippet_patterns):
        return "customer_facing"

    # Internal tier — backend services, workers, pipelines, CLI
    internal_indicators = {
        "services", "workers", "tasks", "jobs", "pipelines",
        "internal", "admin", "cli", "cron", "batch", "etl",
        "migrations", "seeds", "utils", "helpers", "lib",
    }
    if path_parts & internal_indicators:
        return "internal"

    # Default: internal (safer assumption than customer_facing)
    return "internal"


def should_scan_file(file_path: str) -> bool:
    """Check if a file should be scanned based on extension and path.

    Excludes test files, fixture data, JSON data directories,
    archives, and other non-production paths.
    """
    # Check extension
    has_code_ext = any(file_path.endswith(ext) for ext in SCANNABLE_EXTENSIONS)
    has_json_ext = any(file_path.endswith(ext) for ext in JSON_SCANNABLE)

    if not has_code_ext and not has_json_ext:
        return False

    # Normalize path
    path_lower = file_path.lower()
    segments = set(path_lower.replace("\\", "/").split("/"))

    # Skip paths with excluded segments
    if segments & SKIP_PATH_SEGMENTS:
        return False

    # Skip data directories
    for data_path in SKIP_DATA_PATHS:
        if data_path in path_lower:
            return False

    # JSON files: only scan config-like files (package.json, tsconfig, etc.)
    # Skip large data JSON files
    if has_json_ext and not has_code_ext:
        filename = file_path.split("/")[-1].lower()
        config_json_names = {
            "package.json", "tsconfig.json", "jsconfig.json",
            "composer.json", ".eslintrc.json", "tslint.json",
        }
        if filename not in config_json_names:
            return False

    return True
