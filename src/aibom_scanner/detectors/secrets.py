"""Detect secrets management practices and hardcoded API keys in repositories."""
import os
import re
from dataclasses import dataclass


@dataclass
class SecretsManagementDetection:
    method: str  # e.g., "vault", "aws_secrets_manager", "env_vars", "dotenv"
    evidence_type: str  # "file_path", "dependency", "code_pattern", "gitignore", "hardcoded_key"
    file_path: str
    confidence: float
    detail: str
    repo: str = ""
    raw_value: str = ""  # full key value (for hardcoded keys only)
    redacted_value: str = ""  # partially redacted (for display)


# --- Tier 1: File path indicators ---

FILE_PATH_INDICATORS = [
    ("vault", "vault-agent.hcl", 0.9),
    ("vault", "vault-config.hcl", 0.9),
    ("vault", ".vault-token", 1.0),
    ("vault", "vault.hcl", 0.9),
    ("sops", ".sops.yaml", 1.0),
    ("doppler", "doppler.yaml", 1.0),
    ("infisical", ".infisical.json", 1.0),
    ("1password", ".op/", 0.9),
    ("1password", "op-config.yaml", 0.9),
    ("dotenv_config", ".env.example", 0.8),
    ("dotenv_config", ".env.template", 0.8),
    ("dotenv_config", ".env.sample", 0.8),
]

# --- Tier 2: Dependency indicators ---

SECRETS_MGMT_DEPS = {
    # Python
    "hvac": "vault",
    "python-dotenv": "dotenv",
    "python-decouple": "env_vars",
    "pydantic-settings": "env_vars",
    "azure-keyvault-secrets": "azure_keyvault",
    "azure-identity": "azure_keyvault",
    "google-cloud-secret-manager": "gcp_secret_manager",
    # Node / npm
    "dotenv": "dotenv",
    "node-vault": "vault",
    "@hashicorp/vault": "vault",
    "@aws-sdk/client-secrets-manager": "aws_secrets_manager",
    "@azure/keyvault-secrets": "azure_keyvault",
    "@1password/sdk": "1password",
}

# --- Tier 3: Code pattern indicators ---

CODE_PATTERNS = [
    (r"os\.environ\.get\(|os\.getenv\(|os\.environ\[", "env_vars", 0.8),
    (r"process\.env\.", "env_vars", 0.8),
    (r"vault_client|hvac\.Client|vault\.read\(|vault\.secrets", "vault", 0.9),
    (r"get_secret_value|secretsmanager", "aws_secrets_manager", 0.9),
    (r"SecretClient\(|\.get_secret\(", "azure_keyvault", 0.9),
    (r"load_dotenv\(|dotenv\.config\(", "dotenv", 0.8),
    (r"SecretManagerServiceClient|access_secret_version", "gcp_secret_manager", 0.9),
]

# --- Tier 4: .gitignore patterns ---

GITIGNORE_SECRETS_PATTERNS = [
    ".env",
    ".env.*",
    ".env.local",
    "*.pem",
    "*.key",
    "secrets.json",
    ".secrets",
]

# --- Hardcoded key patterns (negative signals) ---

HARDCODED_KEY_PATTERNS = [
    (r"(?:sk-[a-zA-Z0-9]{20,})", "openai"),
    (r"(?:sk-proj-[A-Za-z0-9_\-]{20,})", "openai"),
    (r"(?:sk-ant-[a-zA-Z0-9\-]{20,})", "anthropic"),
    (r"(?:AIza[0-9A-Za-z\-_]{35})", "google"),
    (r"(?:AKIA[0-9A-Z]{16})", "aws"),
]


# A quoted string literal of 8+ characters assigned to a credential-looking name (`api_key="..."`, `"token": "..."`),
# in single, double or backtick quotes, with an optional f / r / b string prefix.
# Env lookups such as os.environ["API_KEY"] never match: the value must be a quoted literal after `=` or `:`.
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"""((?:api[_-]?key|secret|token|password|passwd|authorization|bearer|credential)[\w-]*["']?\s*[=:]\s*(?:rf|fr|rb|br|f|r|b)?)"""
    r"""(["'`])((?:(?!\2).){8,})\2""",
    re.IGNORECASE,
)


# An unquoted value after a credential-looking name (`export NAME=value`, compose `- NAME=value`, YAML `NAME: value`).
# Only token-shaped values are masked, so variable references and plain words stay intact.
_UNQUOTED_CREDENTIAL = re.compile(
    r"""((?:api[_-]?key|secret|token|password|passwd|credential)[\w-]{0,64}\s*[=:]\s*)(?!["'`$({<])([^\s"'`,;(){}\[\]]{8,})(?![\[(\w.])""",
    re.IGNORECASE,
)
# A Bearer or Basic credential inside a longer string (`curl -H "Authorization: Bearer ..."`).
_AUTH_SCHEME_TOKEN = re.compile(r"""\b((?:bearer|basic)\s+)([A-Za-z0-9._~+/=-]{8,})""", re.IGNORECASE)


# Masking only (not detection): any sk- token of 20+ characters, whatever the prefix or separators.
_BROAD_SK_KEY = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}")


# Credentials inside a URL: the userinfo part (`https://user:pass@host`) and credential-named query parameters.
_URL_USERINFO = re.compile(r"(?<=://)[^\s/?#@\"'`]+@")
_URL_CREDENTIAL_PARAM = re.compile(
    r"([?&](?:api[_-]?key|key|token|access[_-]?token|secret|password|passwd|auth|sig|signature)=)[^&#\s\"'`]+",
    re.IGNORECASE,
)

# A dict literal assigned to `headers` on one line; every quoted value in it is masked, whatever the header name.
_HEADERS_DICT = re.compile(r"""(headers["']?\s*[=:]\s*\{)([^{}]*)(\})""", re.IGNORECASE)
_DICT_VALUE = re.compile(r"""(:\s*(?:rf|fr|rb|br|f|r|b)?)(["'`])((?:(?!\2).)+)\2""")

# A quoted literal passed positionally (after `(` or `,`, before `,` or `)`) that looks like a token: 20+ token
# characters with a letter and a digit, and an uppercase letter or 32+ characters. Env var names
# (`os.getenv("API_KEY_2")`) and model ids (`"claude-3-5-sonnet-20241022"`) are left alone.
_POSITIONAL_LITERAL = re.compile(r"""([(,]\s*(?:rf|fr|rb|br|f|r|b)?)(["'`])([A-Za-z0-9_\-+/=.~]{20,})\2(?=\s*[,)])""")


def _token_shaped(value: str) -> bool:
    return (
        bool(re.search(r"[A-Za-z]", value)) and bool(re.search(r"[0-9]", value))
        and not re.fullmatch(r"[A-Z0-9_]+", value)
        and (bool(re.search(r"[A-Z]", value)) or len(value) >= 32)
    )


def _mask_if_token(m: re.Match) -> str:
    return m.group(1) + ("<redacted>" if _token_shaped(m.group(2)) else m.group(2))


def mask_secrets(text: str) -> str:
    """Replace key-shaped strings and credential values with "<redacted>". For text that gets serialized.

    Masked: known key shapes, quoted values assigned to credential-looking names, URL userinfo and credential
    query parameters, every value in a one-line `headers` dict, and token-shaped literals passed positionally."""
    text = _BROAD_SK_KEY.sub("<redacted>", text)  # first, so a key with "_" or "-proj-" is masked whole
    for pattern, _provider in HARDCODED_KEY_PATTERNS:
        text = re.sub(pattern, "<redacted>", text)
    text = _URL_USERINFO.sub("<redacted>@", text)
    text = _URL_CREDENTIAL_PARAM.sub(r"\1<redacted>", text)
    text = _HEADERS_DICT.sub(lambda m: m.group(1) + _DICT_VALUE.sub(r"\1\2<redacted>\2", m.group(2)) + m.group(3), text)
    text = _POSITIONAL_LITERAL.sub(
        lambda m: m.group(1) + m.group(2) + ("<redacted>" if _token_shaped(m.group(3)) else m.group(3)) + m.group(2),
        text,
    )
    text = _CREDENTIAL_ASSIGNMENT.sub(r"\1\2<redacted>\2", text)
    text = _UNQUOTED_CREDENTIAL.sub(_mask_if_token, text)
    return _AUTH_SCHEME_TOKEN.sub(_mask_if_token, text)


def redact_key(value: str) -> str:
    """Partially redact a key for display: first 4 + last 2 chars."""
    return value[:4] + "..." + value[-2:]


def detect_secrets_management(
    file_paths: list[str],
    file_contents: dict[str, str] | None = None,
    gitignore_content: str | None = None,
) -> list[SecretsManagementDetection]:
    """Detect secrets management practices from repo file paths, contents, and .gitignore.

    Uses four tiers of detection (file paths, dependencies, code patterns, .gitignore)
    without making any extra API calls — reuses already-fetched data.
    """
    detections: list[SecretsManagementDetection] = []
    seen: set[tuple[str, str, str]] = set()  # (method, evidence_type, file_path)

    def _add(method, evidence_type, file_path, confidence, detail):
        key = (method, evidence_type, file_path)
        if key not in seen:
            seen.add(key)
            detections.append(SecretsManagementDetection(
                method=method,
                evidence_type=evidence_type,
                file_path=file_path,
                confidence=confidence,
                detail=detail,
            ))

    # Tier 1: File path indicators
    for method, indicator, confidence in FILE_PATH_INDICATORS:
        for fp in file_paths:
            if indicator in fp:
                _add(method, "file_path", fp, confidence, f"Found {indicator} in repository")
                break

    # Tier 2: Dependency scanning (reuses already-fetched dependency files)
    if file_contents:
        for fp, content in file_contents.items():
            _scan_dependencies_for_secrets(fp, content, detections, seen)

    # Tier 3: Code pattern detection (reuses already-fetched file contents)
    if file_contents:
        for fp, content in file_contents.items():
            for pattern, method, confidence in CODE_PATTERNS:
                if re.search(pattern, content):
                    _add(method, "code_pattern", fp, confidence,
                         f"Code pattern for {method} detected")

    # Tier 4: .gitignore check
    if gitignore_content:
        lines = [line.strip() for line in gitignore_content.splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        for secret_pattern in GITIGNORE_SECRETS_PATTERNS:
            for line in lines:
                if secret_pattern in line or line == secret_pattern:
                    _add("gitignore", "gitignore", ".gitignore", 0.7,
                         f"'{secret_pattern}' is gitignored — credential hygiene signal")
                    break

    return detections


def _scan_dependencies_for_secrets(
    file_path: str,
    content: str,
    detections: list[SecretsManagementDetection],
    seen: set[tuple[str, str, str]],
) -> None:
    """Check dependency files for secrets management packages."""
    basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    content_lower = content.lower()

    for package, method in SECRETS_MGMT_DEPS.items():
        package_lower = package.lower()
        found = False

        if basename == "requirements.txt":
            for line in content.splitlines():
                if line.strip().lower().startswith(package_lower):
                    found = True
                    break
        elif basename == "package.json":
            if f'"{package}"' in content or f"'{package}'" in content:
                found = True
        elif basename == "pyproject.toml":
            if package_lower in content_lower:
                found = True
        elif basename == "Pipfile":
            if package_lower in content_lower:
                found = True
        elif basename == "go.mod":
            if package_lower in content_lower:
                found = True
        elif basename == "Cargo.toml":
            if package_lower in content_lower:
                found = True

        if found:
            key = (method, "dependency", file_path)
            if key not in seen:
                seen.add(key)
                detections.append(SecretsManagementDetection(
                    method=method,
                    evidence_type="dependency",
                    file_path=file_path,
                    confidence=0.9,
                    detail=f"Package '{package}' found in {basename}",
                ))


# --- False-positive filters for hardcoded key detection ---

_DOC_EXTENSIONS = {".md", ".mdx", ".rst", ".txt", ".adoc", ".rdoc"}

_PLACEHOLDER_WORDS = {
    "YOUR", "HERE", "EXAMPLE", "REPLACE", "PLACEHOLDER", "XXXX",
    "TODO", "FIXME", "CHANGE", "INSERT", "PASTE", "DUMMY", "FAKE", "TEST",
}

_VALIDATION_CONTEXTS = [
    "startswith(", "starts_with(", "beginswith(",
    "endswith(", "match(", "test(", "search(",
    "prefix", "format:", "example:",
]


def _is_doc_file(file_path: str) -> bool:
    """Return True if file_path has a documentation extension."""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in _DOC_EXTENSIONS


def _is_placeholder(value: str) -> bool:
    """Return True if the matched key value contains placeholder words."""
    upper = value.upper()
    return any(word in upper for word in _PLACEHOLDER_WORDS)


def _is_validation_context(line: str) -> bool:
    """Return True if the source line is a format-validation or doc context."""
    lower = line.lower()
    return any(ctx in lower for ctx in _VALIDATION_CONTEXTS)


def _get_line_at_offset(content: str, offset: int) -> str:
    """Return the full source line containing the character at offset."""
    line_start = content.rfind("\n", 0, offset) + 1
    line_end = content.find("\n", offset)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end]


def detect_hardcoded_keys(file_path: str, content: str) -> list[SecretsManagementDetection]:
    """Scan file content for hardcoded API keys. Returns detections with raw + redacted values.

    Filters out false positives from documentation files, placeholder values,
    and validation/comparison contexts.
    """
    if _is_doc_file(file_path):
        return []

    detections = []

    for pattern, provider in HARDCODED_KEY_PATTERNS:
        for match in re.finditer(pattern, content):
            raw_value = match.group(0)
            if _is_placeholder(raw_value):
                continue
            line = _get_line_at_offset(content, match.start())
            if _is_validation_context(line):
                continue
            detections.append(SecretsManagementDetection(
                method=f"hardcoded_{provider}_key",
                evidence_type="hardcoded_key",
                file_path=file_path,
                confidence=1.0,
                detail=f"Hardcoded {provider} API key found",
                raw_value=raw_value,
                redacted_value=redact_key(raw_value),
            ))

    return detections
