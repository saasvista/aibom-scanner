"""Classify compliance risks from AI detections — 34 rules with framework references."""

import re
from aibom_scanner.models import Severity


RISK_IMPACT_METHODOLOGY = {
    "data_privacy": {
        "regulatory_basis": "GDPR Art. 83: up to 4% of annual global turnover or EUR 20M. EU AI Act Art. 99: up to 3% of turnover or EUR 15M.",
        "benchmark": "IBM Cost of Data Breach 2023: $4.45M average, $165K median for companies <500 employees.",
    },
    "security": {
        "regulatory_basis": "State breach notification laws (all 50 US states). GDPR Art. 33-34.",
        "benchmark": "IBM 2023: $4.45M average breach. Ponemon: $180 per compromised record.",
    },
    "model_governance": {
        "regulatory_basis": "EU AI Act Art. 9: risk management system required for high-risk AI.",
        "benchmark": "Model failures in production: median customer impact 4-8 hours downtime.",
    },
    "transparency": {
        "regulatory_basis": "EU AI Act Art. 52: transparency obligations. Art. 13: transparency for high-risk AI users.",
        "benchmark": "FTC enforcement actions for undisclosed AI use: $5K-$50K per violation.",
    },
    "accountability": {
        "regulatory_basis": "EU AI Act Art. 14: human oversight. NIST AI RMF GOVERN functions.",
        "benchmark": "Organizations without AI risk owners average 2.3x longer incident response (Gartner 2024).",
    },
    "bias_fairness": {
        "regulatory_basis": "EU AI Act Art. 10: data governance. NYC Local Law 144. EEOC guidance.",
        "benchmark": "AI discrimination lawsuits: $1M-$100M+. 15-30% trust decline (Edelman).",
    },
    "compliance": {
        "regulatory_basis": "EU AI Act Art. 99: up to 3% of turnover or EUR 15M for AI-specific violations.",
        "benchmark": "Export control violations: up to $300K per violation or 2x transaction value.",
    },
    "agentic_ai_governance": {
        "regulatory_basis": "EU AI Act Art. 14: human oversight for high-risk AI. NIST AI RMF GOVERN-1/MANAGE-1.",
        "benchmark": "Autonomous AI agent failures: 3-10x single-model blast radius.",
    },
}

# Patterns that indicate user input flows to AI
USER_INPUT_PATTERNS = re.compile(
    r'(request\.body|req\.body|request\.json|request\.form|request\.get_json'
    r'|user_input|user_message|user_prompt|user_query'
    r'|input\s*=\s*input\(|getline|readline'
    r'|st\.text_input|st\.text_area'
    r'|@app\.(post|put|patch)\s*\()',
    re.IGNORECASE,
)

# Patterns that indicate customer/PII data flows to AI
DATA_FLOW_PATTERNS = re.compile(
    r'(customer_data|user_data|pii|personal_data|email_address|phone_number|ssn|credit_card'
    r'|\.query\(|\.execute\(|\.findOne\(|\.findMany\('
    r'|db\.\w+\.\w+|database\.\w+|SELECT\s+\w+\s+FROM|INSERT\s+INTO)',
    re.IGNORECASE,
)


RISK_RULES = [
    # --- Data Privacy ---
    {
        "category": "data_privacy",
        "title": "Customer data sent to external AI provider without DPA",
        "severity": Severity.HIGH,
        "providers": ["openai", "anthropic", "google_ai", "azure_openai", "cohere", "mistral", "groq", "together_ai", "fireworks", "replicate", "zhipu", "iflytek", "sensetime", "alibaba_qwen", "baidu_ernie", "deepseek", "moonshot", "minimax", "baichuan", "yi"],
        "evidence_qualifier": "data_to_ai",
        "remediation": "Verify current DPA status with each AI provider. Where missing, execute a DPA. Implement data anonymization before API calls.",
        "framework_refs": ["NIST-MAP-3.1", "ISO-42001-A.7.5", "EU-AI-ACT-ART-10"],
    },
    {
        "category": "data_privacy",
        "title": "No data classification policy for AI-processed information",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "evidence_qualifier": "data_to_ai",
        "remediation": "Create a data classification scheme. Label data before it enters AI pipelines. Block sensitive/PII categories from external models.",
        "framework_refs": ["NIST-GOVERN-1.5", "ISO-42001-A.7.4", "EU-AI-ACT-ART-10"],
    },
    {
        "category": "data_privacy",
        "title": "AI provider may retain prompts for training",
        "severity": Severity.MEDIUM,
        "providers": ["openai", "anthropic", "google_ai", "cohere", "mistral", "zhipu", "iflytek", "sensetime", "alibaba_qwen", "baidu_ernie", "deepseek", "moonshot", "minimax", "baichuan", "yi"],
        "remediation": "Review each provider's data retention policy. Opt out of training data usage where possible.",
        "framework_refs": ["NIST-MAP-3.2", "ISO-42001-A.7.5"],
    },
    {
        "category": "data_privacy",
        "title": "Cross-border data transfer via AI provider",
        "severity": Severity.MEDIUM,
        "providers": ["openai", "anthropic", "google_ai", "azure_openai", "cohere", "replicate", "together_ai", "zhipu", "iflytek", "sensetime", "alibaba_qwen", "baidu_ernie", "deepseek", "moonshot", "minimax", "baichuan", "yi"],
        "remediation": "Identify data residency requirements. Confirm provider processing locations. Implement Standard Contractual Clauses where needed.",
        "framework_refs": ["NIST-GOVERN-1.6", "ISO-42001-A.7.5", "EU-AI-ACT-ART-10"],
    },
    # --- Model Governance ---
    {
        "category": "model_governance",
        "title": "AI model usage without governance framework",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "remediation": "Establish an AI governance policy covering model selection, approval, monitoring, and deprecation.",
        "framework_refs": ["NIST-GOVERN-1.1", "ISO-42001-5.1", "EU-AI-ACT-ART-9"],
    },
    {
        "category": "model_governance",
        "title": "No model inventory or registry maintained",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Create a registry of all AI models: provider, version, purpose, and data flows.",
        "framework_refs": ["NIST-GOVERN-1.2", "ISO-42001-A.6.2", "EU-AI-ACT-ART-11"],
    },
    {
        "category": "model_governance",
        "title": "Multiple AI providers increase governance complexity",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "min_providers": 2,
        "remediation": "Consolidate provider management. Establish per-provider risk assessments.",
        "framework_refs": ["NIST-GOVERN-1.3", "ISO-42001-A.6.2"],
    },
    {
        "category": "model_governance",
        "title": "No model versioning or change management process",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Pin model versions in code. Establish change management for model upgrades.",
        "framework_refs": ["NIST-MANAGE-2.1", "ISO-42001-A.8.4"],
    },
    {
        "category": "model_governance",
        "title": "AI orchestration framework adds supply chain risk",
        "severity": Severity.MEDIUM,
        "providers": ["langchain", "llamaindex", "crewai", "autogen", "langgraph", "semantic_kernel"],
        "remediation": "Audit orchestration framework dependencies. Pin versions. Monitor security advisories.",
        "framework_refs": ["NIST-MAP-2.3", "ISO-42001-A.8.2"],
    },
    # --- Security ---
    {
        "category": "security",
        "title": "API keys potentially exposed in source code",
        "severity": Severity.CRITICAL,
        "providers": ["*"],
        "remediation": "Move all API keys to a secrets manager. Rotate any keys found in code. Add secret scanning to CI/CD.",
        "framework_refs": ["NIST-MANAGE-4.1", "ISO-42001-A.8.6", "EU-AI-ACT-ART-15"],
    },
    {
        "category": "security",
        "title": "No input validation before AI model calls",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "evidence_qualifier": "user_facing_ai",
        "remediation": "Implement prompt injection defenses. Validate and sanitize all user input before passing to AI models.",
        "framework_refs": ["NIST-MANAGE-4.1", "ISO-42001-A.8.6", "EU-AI-ACT-ART-15"],
    },
    {
        "category": "security",
        "title": "No output validation from AI model responses",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "evidence_qualifier": "user_facing_ai",
        "remediation": "Validate and sanitize AI model outputs. Implement guardrails for harmful content.",
        "framework_refs": ["NIST-MEASURE-2.6", "ISO-42001-A.8.5", "EU-AI-ACT-ART-15"],
    },
    {
        "category": "security",
        "title": "AI dev tools may transmit code to external services",
        "severity": Severity.MEDIUM,
        "detection_types": ["dev_tool"],
        "providers": [],
        "remediation": "Review AI dev tool data transmission policies. Establish approved tool list.",
        "framework_refs": ["NIST-MANAGE-4.2", "ISO-42001-A.8.6"],
    },
    # --- Transparency ---
    {
        "category": "transparency",
        "title": "No documentation of AI system purposes and limitations",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "remediation": "Document purpose, capabilities, and limitations of each AI integration.",
        "framework_refs": ["NIST-MAP-1.1", "ISO-42001-A.6.1", "EU-AI-ACT-ART-13"],
    },
    {
        "category": "transparency",
        "title": "No disclosure to users about AI-generated content",
        "severity": Severity.MEDIUM,
        "providers": ["openai", "anthropic", "google_ai", "cohere", "mistral", "groq", "together_ai", "zhipu", "iflytek", "sensetime", "alibaba_qwen", "baidu_ernie", "deepseek", "moonshot", "minimax", "baichuan", "yi"],
        "remediation": "Implement clear disclosure when content is AI-generated. Update terms of service.",
        "framework_refs": ["NIST-MAP-1.6", "ISO-42001-A.6.1", "EU-AI-ACT-ART-52"],
    },
    {
        "category": "transparency",
        "title": "AI decision logging not implemented",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Log AI model inputs (sanitized), outputs, and decision rationale.",
        "framework_refs": ["NIST-MEASURE-2.5", "ISO-42001-A.8.3", "EU-AI-ACT-ART-12"],
    },
    # --- Accountability ---
    {
        "category": "accountability",
        "title": "No designated AI risk owner or oversight role",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "remediation": "Assign an AI risk owner for governance, monitoring, and incident response.",
        "framework_refs": ["NIST-GOVERN-2.1", "ISO-42001-5.3", "EU-AI-ACT-ART-9"],
    },
    {
        "category": "accountability",
        "title": "No AI incident response plan",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Develop an AI-specific incident response plan covering model failures and data breaches.",
        "framework_refs": ["NIST-MANAGE-4.3", "ISO-42001-A.9.3"],
    },
    {
        "category": "accountability",
        "title": "No human oversight mechanism for AI decisions",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Implement human-in-the-loop controls for high-stakes AI decisions.",
        "framework_refs": ["NIST-GOVERN-2.2", "ISO-42001-A.9.1", "EU-AI-ACT-ART-14"],
    },
    # --- Bias & Fairness ---
    {
        "category": "bias_fairness",
        "title": "No bias testing or fairness evaluation for AI outputs",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Establish bias testing procedures. Monitor for disparate impact.",
        "framework_refs": ["NIST-MEASURE-2.7", "ISO-42001-A.9.4", "EU-AI-ACT-ART-10"],
    },
    {
        "category": "bias_fairness",
        "title": "Using self-hosted models without bias evaluation",
        "severity": Severity.MEDIUM,
        "providers": ["huggingface"],
        "remediation": "Evaluate open-source models for bias before deployment.",
        "framework_refs": ["NIST-MEASURE-2.7", "ISO-42001-A.9.4", "EU-AI-ACT-ART-10"],
    },
    # --- Export Compliance & Data Sovereignty ---
    {
        "category": "compliance",
        "title": "US Entity List violation — prohibited Chinese AI provider",
        "severity": Severity.CRITICAL,
        "providers": ["zhipu", "iflytek", "sensetime"],
        "remediation": "IMMEDIATE ACTION: Provider is on the US BIS Entity List. Remove all integrations. Revoke API keys. Document removal. Consult export compliance counsel.",
        "framework_refs": ["NIST-GOVERN-1.6", "ISO-42001-A.7.3", "EU-AI-ACT-ART-5"],
    },
    {
        "category": "compliance",
        "title": "Chinese AI provider — data sovereignty risk",
        "severity": Severity.HIGH,
        "providers": ["alibaba_qwen", "baidu_ernie", "deepseek", "moonshot", "minimax", "baichuan", "yi"],
        "remediation": "Data sent to these providers is stored on Chinese servers subject to Chinese law. Evaluate data classification requirements.",
        "framework_refs": ["NIST-GOVERN-1.6", "ISO-42001-A.7.5", "EU-AI-ACT-ART-10"],
    },
    {
        "category": "data_privacy",
        "title": "No DPA available — Chinese AI provider",
        "severity": Severity.HIGH,
        "providers": ["alibaba_qwen", "baidu_ernie", "deepseek", "moonshot", "minimax", "baichuan", "yi", "zhipu", "iflytek", "sensetime"],
        "remediation": "Chinese AI providers do not offer GDPR/CCPA-compatible DPAs.",
        "framework_refs": ["NIST-MAP-3.1", "ISO-42001-A.7.5", "EU-AI-ACT-ART-10"],
    },
    {
        "category": "compliance",
        "title": "AWS Bedrock usage requires additional compliance review",
        "severity": Severity.MEDIUM,
        "providers": ["aws_bedrock"],
        "remediation": "Review AWS Bedrock terms, shared responsibility model, and compliance certifications.",
        "framework_refs": ["NIST-GOVERN-1.4", "ISO-42001-A.7.3"],
    },
    {
        "category": "compliance",
        "title": "EU AI Act high-risk classification may apply",
        "severity": Severity.HIGH,
        "providers": ["*"],
        "evidence_qualifier": "user_facing_ai",
        "remediation": "Assess whether AI use cases fall under EU AI Act high-risk categories.",
        "framework_refs": ["EU-AI-ACT-ART-6", "EU-AI-ACT-ART-43"],
    },
    # --- Agentic AI Governance ---
    {
        "category": "agentic_ai_governance",
        "title": "Agentic AI framework without human oversight controls",
        "severity": Severity.HIGH,
        "providers": ["crewai", "autogen", "langgraph", "semantic_kernel", "mcp"],
        "remediation": "Implement HITL checkpoints, approval gates before external actions, and kill switches.",
        "framework_refs": ["NIST-GOVERN-2.2", "ISO-42001-A.9.1", "EU-AI-ACT-ART-14"],
    },
    {
        "category": "agentic_ai_governance",
        "title": "Multi-agent system increases blast radius of failures",
        "severity": Severity.HIGH,
        "providers": ["crewai", "autogen"],
        "remediation": "Implement per-agent output validation, inter-agent message sanitization, and circuit breakers.",
        "framework_refs": ["NIST-MANAGE-4.1", "ISO-42001-A.8.5", "EU-AI-ACT-ART-15"],
    },
    {
        "category": "agentic_ai_governance",
        "title": "AI agent tool use without access controls",
        "severity": Severity.MEDIUM,
        "providers": ["crewai", "autogen", "langgraph", "semantic_kernel"],
        "remediation": "Implement least-privilege tool permissions, sandboxing, and audit logging.",
        "framework_refs": ["NIST-MANAGE-4.2", "ISO-42001-A.8.6"],
    },
    {
        "category": "agentic_ai_governance",
        "title": "Agentic workflow lacks observability and tracing",
        "severity": Severity.MEDIUM,
        "providers": ["crewai", "autogen", "langgraph", "semantic_kernel"],
        "remediation": "Implement step-level logging with agent identity, decision rationale, and tool calls.",
        "framework_refs": ["NIST-MEASURE-2.5", "ISO-42001-A.8.3", "EU-AI-ACT-ART-12"],
    },
    {
        "category": "agentic_ai_governance",
        "title": "MCP server exposes tools without governance controls",
        "severity": Severity.MEDIUM,
        "providers": ["mcp"],
        "remediation": "Implement auth on MCP endpoints, restrict tool access, log invocations, establish approval gates.",
        "framework_refs": ["NIST-MANAGE-4.2", "ISO-42001-A.8.6", "EU-AI-ACT-ART-14"],
    },
    # --- Operational Monitoring ---
    {
        "category": "model_governance",
        "title": "No model performance monitoring or accuracy tracking",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Implement model performance monitoring: latency, error rates, quality metrics.",
        "framework_refs": ["NIST-MEASURE-2.1", "ISO-42001-A.8.3", "EU-AI-ACT-ART-15"],
    },
    {
        "category": "model_governance",
        "title": "No AI risk assessment or prioritization framework",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Establish formal AI risk assessment: classify by risk level, prioritize remediation.",
        "framework_refs": ["NIST-MANAGE-1.1", "ISO-42001-A.7.3", "EU-AI-ACT-ART-9"],
    },
    {
        "category": "model_governance",
        "title": "No model drift detection or retraining triggers",
        "severity": Severity.MEDIUM,
        "providers": ["*"],
        "remediation": "Monitor output distributions, establish baselines, configure drift alerts.",
        "framework_refs": ["NIST-MANAGE-3.1", "ISO-42001-A.8.3", "EU-AI-ACT-ART-15"],
    },
]


# --- Consolidation Rules ---
CONSOLIDATION_RULES = [
    {
        "anchor": "AI model usage without governance framework",
        "absorbs": [
            "No model inventory or registry maintained",
            "Multiple AI providers increase governance complexity",
            "No model versioning or change management process",
            "AI orchestration framework adds supply chain risk",
            "No bias testing or fairness evaluation for AI outputs",
            "Using self-hosted models without bias evaluation",
            "No model performance monitoring or accuracy tracking",
            "No AI risk assessment or prioritization framework",
            "No model drift detection or retraining triggers",
        ],
    },
    {
        "anchor": "No documentation of AI system purposes and limitations",
        "absorbs": [
            "No disclosure to users about AI-generated content",
            "AI decision logging not implemented",
        ],
    },
    {
        "anchor": "No designated AI risk owner or oversight role",
        "absorbs": [
            "No AI incident response plan",
            "No human oversight mechanism for AI decisions",
        ],
    },
    {
        "anchor": "Customer data sent to external AI provider without DPA",
        "absorbs": [
            "Cross-border data transfer via AI provider",
            "AWS Bedrock usage requires additional compliance review",
        ],
    },
    {
        "anchor": "No input validation before AI model calls",
        "absorbs": [
            "No output validation from AI model responses",
            "EU AI Act high-risk classification may apply",
        ],
    },
    {
        "anchor": "API keys potentially exposed in source code",
        "absorbs": [
            "AI dev tools may transmit code to external services",
        ],
        "alt_anchors": [
            "API key management — secrets manager detected",
            "API key management — env-only, no secrets manager",
        ],
    },
    {"anchor": "No data classification policy for AI-processed information", "absorbs": []},
    {"anchor": "AI provider may retain prompts for training", "absorbs": []},
    {"anchor": "US Entity List violation — prohibited Chinese AI provider", "absorbs": []},
    {
        "anchor": "Chinese AI provider — data sovereignty risk",
        "absorbs": ["No DPA available — Chinese AI provider"],
    },
    {
        "anchor": "Agentic AI framework without human oversight controls",
        "absorbs": [
            "Multi-agent system increases blast radius of failures",
            "AI agent tool use without access controls",
            "Agentic workflow lacks observability and tracing",
            "MCP server exposes tools without governance controls",
        ],
    },
]


def consolidate_risks(raw_risks: list[dict]) -> list[dict]:
    """Merge related raw risks into anchor findings for deterministic consolidation."""
    risk_by_title: dict[str, dict] = {r["title"]: r for r in raw_risks}
    absorbed_titles: set[str] = set()

    consolidated = []
    for rule in CONSOLIDATION_RULES:
        anchor_title = rule["anchor"]
        anchor = risk_by_title.get(anchor_title)
        if not anchor:
            for alt in rule.get("alt_anchors", []):
                anchor = risk_by_title.get(alt)
                if anchor:
                    break
        if not anchor:
            continue

        merged = dict(anchor)
        merged["framework_refs"] = list(anchor.get("framework_refs", []))
        merged["affected_providers"] = list(anchor.get("affected_providers", []))
        merged["remediation"] = anchor.get("remediation", "")

        for sub_title in rule["absorbs"]:
            sub = risk_by_title.get(sub_title)
            if not sub:
                continue
            absorbed_titles.add(sub_title)
            for ref in sub.get("framework_refs", []):
                if ref not in merged["framework_refs"]:
                    merged["framework_refs"].append(ref)
            for prov in sub.get("affected_providers", []):
                if prov not in merged["affected_providers"]:
                    merged["affected_providers"].append(prov)
            if sub.get("remediation") and sub["remediation"] not in merged["remediation"]:
                merged["remediation"] += " " + sub["remediation"]
            if not merged.get("mitigation_status") and _severity_rank(sub.get("severity")) > _severity_rank(merged.get("severity")):
                merged["severity"] = sub["severity"]

        consolidated.append(merged)

    anchor_titles = set()
    for rule in CONSOLIDATION_RULES:
        anchor_titles.add(rule["anchor"])
        for alt in rule.get("alt_anchors", []):
            anchor_titles.add(alt)

    for r in raw_risks:
        if r["title"] not in absorbed_titles and r["title"] not in anchor_titles:
            consolidated.append(r)

    return consolidated


def _severity_rank(severity) -> int:
    if severity is None:
        return 0
    val = severity.value if hasattr(severity, "value") else str(severity)
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(val, 0)


def _check_evidence_qualifier(qualifier: str, code_contexts: list[str]) -> bool:
    if not qualifier or not code_contexts:
        return False
    combined = "\n".join(code_contexts)
    if qualifier == "user_facing_ai":
        return bool(USER_INPUT_PATTERNS.search(combined))
    elif qualifier == "data_to_ai":
        return bool(DATA_FLOW_PATTERNS.search(combined))
    return False


_SEVERITY_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
}

_REAL_SECRETS_MANAGERS = {
    "vault", "aws_secrets_manager", "azure_keyvault",
    "gcp_secret_manager", "sops", "doppler", "1password", "infisical",
}

_ENV_ONLY_METHODS = {"dotenv", "dotenv_config", "env_vars", "gitignore"}


def classify_risks(
    detected_providers: list[str],
    detections: list = None,
    secrets_management: list = None,
    code_contexts: list[str] = None,
) -> list[dict]:
    """Generate risk findings from detected AI providers and code evidence."""
    risks = []
    num_providers = len(set(detected_providers))
    _code_contexts = code_contexts or []

    for rule in RISK_RULES:
        if rule.get("min_providers") and num_providers < rule["min_providers"]:
            continue

        rule_providers = rule.get("providers", [])
        if rule_providers and "*" not in rule_providers:
            if not any(p in rule_providers for p in detected_providers):
                continue

        severity = rule["severity"]
        evidence_qualifier = ""
        qualifier = rule.get("evidence_qualifier", "")

        if qualifier and not _check_evidence_qualifier(qualifier, _code_contexts):
            severity = _SEVERITY_DOWNGRADE.get(severity, severity)
            evidence_qualifier = qualifier

        risks.append({
            "category": rule["category"],
            "title": rule["title"],
            "severity": severity,
            "remediation": rule["remediation"],
            "framework_refs": rule.get("framework_refs", []),
            "affected_providers": (
                detected_providers if "*" in rule_providers
                else [p for p in detected_providers if p in rule_providers]
            ),
            "evidence_qualifier": evidence_qualifier,
        })

    if secrets_management is not None:
        _adjust_credential_risk(risks, secrets_management)

    return risks


def _adjust_credential_risk(risks: list[dict], secrets_evidence: list) -> None:
    """Adjust credential risk based on secrets management evidence."""
    has_real = any(getattr(e, "method", "") in _REAL_SECRETS_MANAGERS for e in secrets_evidence) if secrets_evidence else False
    has_env = any(getattr(e, "method", "") in _ENV_ONLY_METHODS for e in secrets_evidence) if secrets_evidence else False
    has_hardcoded = any(getattr(e, "evidence_type", "") == "hardcoded_key" for e in secrets_evidence) if secrets_evidence else False

    mgmt_methods = sorted({getattr(e, "method", "") for e in (secrets_evidence or []) if getattr(e, "evidence_type", "") != "hardcoded_key"})
    evidence_summary = ", ".join(mgmt_methods) if mgmt_methods else ""

    for risk in risks:
        if risk["title"] == "API keys potentially exposed in source code":
            if has_real and not has_hardcoded:
                risk["severity"] = Severity.LOW
                risk["title"] = "API key management — secrets manager detected"
                risk["mitigation_status"] = "mitigated"
            elif has_real and has_hardcoded:
                risk["severity"] = Severity.HIGH
                risk["mitigation_status"] = "partially_mitigated"
            elif has_env and not has_hardcoded:
                risk["severity"] = Severity.MEDIUM
                risk["title"] = "API key management — env-only, no secrets manager"
                risk["mitigation_status"] = "partially_mitigated"
            elif has_env and has_hardcoded:
                risk["severity"] = Severity.HIGH
                risk["mitigation_status"] = "partially_mitigated"
            elif not has_real and not has_env and not has_hardcoded:
                risk["severity"] = Severity.HIGH
            break
